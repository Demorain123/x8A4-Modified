#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <x8A4/private_record_archive.h>

static void make_record(struct x8A4_target_key_record *r, uint32_t id) {
  memset(r, 0, sizeof(*r));
  r->generated = 1;
  r->key_id = id;
  r->key_sz = 128;
  for (unsigned i = 0; i < 4; ++i) {
    r->key[i] = 0xA1B2C3D4U + i;
    r->iv[i] = 0x10203040U + i;
  }
  r->zero = 0;
  r->pad = 0xDEADBEEFU;
}

static void read_exact_file(int dirfd, const char *name, void *out,
                            size_t expected) {
  int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  assert(fd >= 0);
  struct stat st;
  assert(fstat(fd, &st) == 0 && S_ISREG(st.st_mode));
  assert((st.st_mode & 077) == 0 && st.st_uid == geteuid());
  assert((size_t)st.st_size == expected);
  assert(read(fd, out, expected) == (ssize_t)expected);
  char extra;
  assert(read(fd, &extra, 1) == 0);
  assert(close(fd) == 0);
}

int main(void) {
  char parent[] = "/tmp/x8a4-archive-test-XXXXXX";
  assert(mkdtemp(parent) != NULL);

  char run[256];
  assert(snprintf(run, sizeof(run), "%s/run", parent) > 0);
  int dirfd = x8A4_archive_create_private_dir(run);
  assert(dirfd >= 0);
  struct stat dst;
  assert(fstat(dirfd, &dst) == 0 && S_ISDIR(dst.st_mode));
  assert((dst.st_mode & 077) == 0 && dst.st_uid == geteuid());
  assert(x8A4_archive_create_private_dir(run) < 0); /* no reuse */

  struct x8A4_target_key_record record;
  make_record(&record, 0x8A3);
  assert(x8A4_archive_write_record(dirfd, &record, 7) == 0);
  unsigned char raw[X8A4_RAW_RECORD_BYTES];
  read_exact_file(dirfd, "0x8A3.raw", raw, sizeof(raw));
  assert(memcmp(raw, &record, sizeof(raw)) == 0);

  char metadata[256] = {0};
  int metadata_fd = openat(dirfd, "0x8A3.json", O_RDONLY | O_NOFOLLOW);
  assert(metadata_fd >= 0);
  struct stat metadata_stat;
  assert(fstat(metadata_fd, &metadata_stat) == 0);
  assert(S_ISREG(metadata_stat.st_mode) && metadata_stat.st_uid == geteuid());
  assert((metadata_stat.st_mode & 077) == 0);
  assert(metadata_stat.st_size > 0 && metadata_stat.st_size < (off_t)sizeof(metadata));
  assert(read(metadata_fd, metadata, (size_t)metadata_stat.st_size) == metadata_stat.st_size);
  assert(close(metadata_fd) == 0);
  assert(strstr(metadata, "\"record_id\":\"0x8A3\"") != NULL);
  assert(strstr(metadata, "\"index\":7") != NULL);
  assert(strstr(metadata, "0xA1B2C3D4") == NULL); /* no key text */
  assert(x8A4_archive_write_status(dirfd, 0x8A3, "saved") == 0);
  char status[8] = {0};
  read_exact_file(dirfd, "0x8A3.status", status, 6);
  assert(strcmp(status, "saved\n") == 0);

  assert(x8A4_archive_write_record(dirfd, &record, 7) < 0); /* no overwrite */
  unsigned char raw_after[X8A4_RAW_RECORD_BYTES];
  read_exact_file(dirfd, "0x8A3.raw", raw_after, sizeof(raw_after));
  assert(memcmp(raw, raw_after, sizeof(raw)) == 0);

  char sentinel[256];
  assert(snprintf(sentinel, sizeof(sentinel), "%s/sentinel", parent) > 0);
  int sentinel_fd = open(sentinel, O_WRONLY | O_CREAT | O_EXCL, 0600);
  assert(sentinel_fd >= 0 && write(sentinel_fd, "safe", 4) == 4);
  assert(close(sentinel_fd) == 0);
  char link_path[256];
  assert(snprintf(link_path, sizeof(link_path), "%s/0x8A4.raw", run) > 0);
  assert(symlink(sentinel, link_path) == 0);
  make_record(&record, 0x8A4);
  assert(x8A4_archive_write_private_file(dirfd, "0x8A4.raw", &record,
                                         sizeof(record)) < 0);
  char sentinel_data[5] = {0};
  sentinel_fd = open(sentinel, O_RDONLY | O_NOFOLLOW);
  assert(sentinel_fd >= 0 && read(sentinel_fd, sentinel_data, 4) == 4);
  assert(close(sentinel_fd) == 0 && strcmp(sentinel_data, "safe") == 0);
  assert(unlink(link_path) == 0);

  /* Force a real short/failed write; the partial secret file must be removed. */
  char partial_run[256];
  assert(snprintf(partial_run, sizeof(partial_run), "%s/partial", parent) > 0);
  int partial_dirfd = x8A4_archive_create_private_dir(partial_run);
  assert(partial_dirfd >= 0);
  struct rlimit original_limit, short_limit;
  assert(getrlimit(RLIMIT_FSIZE, &original_limit) == 0);
  short_limit = original_limit;
  short_limit.rlim_cur = 16;
  (void)signal(SIGXFSZ, SIG_IGN);
  assert(setrlimit(RLIMIT_FSIZE, &short_limit) == 0);
  assert(x8A4_archive_write_record(partial_dirfd, &record, 9) != 0);
  assert(setrlimit(RLIMIT_FSIZE, &original_limit) == 0);
  struct stat missing;
  assert(fstatat(partial_dirfd, "0x8A4.raw", &missing, AT_SYMLINK_NOFOLLOW) != 0 &&
         errno == ENOENT);
  assert(fstatat(partial_dirfd, "0x8A4.json", &missing, AT_SYMLINK_NOFOLLOW) != 0 &&
         errno == ENOENT);

  assert(close(partial_dirfd) == 0);
  assert(unlinkat(dirfd, "0x8A3.raw", 0) == 0);
  assert(unlinkat(dirfd, "0x8A3.json", 0) == 0);
  assert(unlinkat(dirfd, "0x8A3.status", 0) == 0);
  assert(close(dirfd) == 0);
  assert(unlink(sentinel) == 0);
  assert(rmdir(run) == 0);
  assert(rmdir(partial_run) == 0);
  assert(rmdir(parent) == 0);
  x8A4_secure_clear(&record, sizeof(record));
  puts("PASS: private 52-byte archive, metadata, no-overwrite, cleanup");
  return 0;
}
