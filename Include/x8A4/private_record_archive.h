#ifndef X8A4_PRIVATE_RECORD_ARCHIVE_H
#define X8A4_PRIVATE_RECORD_ARCHIVE_H

/* Small POSIX writer for local, private 52-byte research records. */
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <x8A4/target_key.h>
#include <x8A4/secure_clear.h>

#define X8A4_RAW_RECORD_BYTES 52U

static inline int x8A4_archive_create_private_dir(const char *path) {
  if (!path || !*path || path[strlen(path) - 1] == '/') return -1;
  if (mkdir(path, 0700) != 0) return -1; /* never reuse or overwrite a run */

  int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) {
    (void)rmdir(path);
    return -1;
  }

  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
      st.st_uid != geteuid() || (st.st_mode & 077) != 0 ||
      fchmod(fd, 0700) != 0 || fstat(fd, &st) != 0 ||
      (st.st_mode & 077) != 0) {
    (void)close(fd);
    (void)rmdir(path);
    return -1;
  }
  return fd;
}

static inline int x8A4_archive_write_all(int fd, const void *data,
                                        size_t length) {
  const unsigned char *p = (const unsigned char *)data;
  size_t written = 0;
  while (written < length) {
    ssize_t n = write(fd, p + written, length - written);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return -1;
    written += (size_t)n;
  }
  return 0;
}

static inline int x8A4_archive_write_private_file(int dirfd, const char *name,
                                                  const void *data,
                                                  size_t length) {
  if (dirfd < 0 || !name || !*name || !data || !length ||
      strchr(name, '/') != NULL)
    return -1;

  int fd = openat(dirfd, name,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) return -1;

  struct stat st;
  int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_uid == geteuid() && st.st_nlink == 1 &&
           fchmod(fd, 0600) == 0 && x8A4_archive_write_all(fd, data, length) == 0 &&
           fsync(fd) == 0;
  if (close(fd) != 0) ok = 0;
  if (!ok) (void)unlinkat(dirfd, name, 0);
  return ok ? 0 : -1;
}

static inline int x8A4_archive_write_record(
    int dirfd, const struct x8A4_target_key_record *record, uint32_t index) {
  if (!record ||
      (record->key_id != 0x8A3 && record->key_id != 0x8A4) ||
      record->generated != 1 ||
      (record->key_sz != 16 && record->key_sz != 128) ||
      sizeof(*record) != X8A4_RAW_RECORD_BYTES)
    return -1;

  char id[8];
  (void)snprintf(id, sizeof(id), "0x%03X", record->key_id);
  char raw_name[16], metadata_name[16];
  (void)snprintf(raw_name, sizeof(raw_name), "%s.raw", id);
  (void)snprintf(metadata_name, sizeof(metadata_name), "%s.json", id);

  /* The struct is packed and statically asserted to 52 bytes by target_key.h.
   * Store its exact bytes; never format KEY or IV into a text stream. */
  if (x8A4_archive_write_private_file(dirfd, raw_name, record,
                                     X8A4_RAW_RECORD_BYTES) != 0)
    return -1;

  char metadata[256];
  int n = snprintf(metadata, sizeof(metadata),
                   "{\"format\":\"x8A4-private-record-v1\","
                   "\"device\":\"iPad13,4\",\"build\":\"21D61\","
                   "\"darwin\":\"23.3.0\",\"record_id\":\"%s\","
                   "\"index\":%u,\"generated\":%u,\"key_sz\":%u,"
                   "\"record_bytes\":52,\"raw_file\":\"%s\"}\n",
                   id, index, record->generated, record->key_sz, raw_name);
  if (n < 0 || (size_t)n >= sizeof(metadata) ||
      x8A4_archive_write_private_file(dirfd, metadata_name, metadata,
                                      (size_t)n) != 0)
    return 1; /* raw record is complete and intentionally preserved */
  return 0;
}

static inline int x8A4_archive_write_status(int dirfd, uint32_t key_id,
                                            const char *status) {
  if (key_id != 0x8A3 && key_id != 0x8A4) return -1;
  const char *name = key_id == 0x8A3 ? "0x8A3.status" : "0x8A4.status";
  if (!status || strchr(status, '\n') || strchr(status, '\r')) return -1;
  char body[96];
  int n = snprintf(body, sizeof(body), "%s\n", status);
  if (n < 0 || (size_t)n >= sizeof(body)) return -1;
  return x8A4_archive_write_private_file(dirfd, name, body, (size_t)n);
}

#endif
