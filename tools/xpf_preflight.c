#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
typedef struct {
	CC_SHA256_CTX context;
} Sha256Context;
#else
#include <openssl/evp.h>
typedef struct {
	EVP_MD_CTX *context;
} Sha256Context;
#endif

#ifndef XPF_PREFLIGHT_VERSION
#define XPF_PREFLIGHT_VERSION "0.1.0"
#endif

#ifndef XPF_PREFLIGHT_SOURCE_COMMIT
#define XPF_PREFLIGHT_SOURCE_COMMIT "unknown"
#endif

#ifndef XPF_ARCHIVE_SHA256
#define XPF_ARCHIVE_SHA256 "unknown"
#endif

#ifndef XPF_EXPECTED_INPUT_SHA256
#define XPF_EXPECTED_INPUT_SHA256 "16e2f6ab693b6d26a038c799e8b17132a5437d4fddd892b90c3d2a6ae8a1843c"
#endif

#define EXPECTED_TARGET "iPad13,4 / iPadOS 17.3.1 / 21D61 (expected target)"
#define MH_MAGIC_64_VALUE UINT32_C(0xfeedfacf)
#define MH_FILESET_VALUE UINT32_C(0x0000000c)
#define LC_UUID_VALUE UINT32_C(0x0000001b)
#define MACH_HEADER_64_SIZE 32U
#define UUID_LOAD_COMMAND_SIZE 24U
#define HASH_BUFFER_SIZE 65536U

typedef struct {
	const char *name;
	uint64_t value;
	char error[256];
	bool resolved;
} Metric;

typedef struct {
	uint64_t size;
	uint32_t cpu_type;
	uint32_t cpu_subtype;
	char uuid[33];
	char sha256[65];
} InputInfo;

/* Intentionally declare only the XPF calls used by this standalone tool.
 * This avoids depending on or dereferencing XPF's private gXPF layout. */
extern int xpf_start_with_kernel_path(const char *kernelPath);
extern uint64_t xpf_item_resolve(const char *name);
extern const char *xpf_get_error(void);
extern void xpf_stop(void);

static const char *const metric_names[] = {
	"kernelConstant.T1SZ_BOOT",
	"kernelStruct.task.itk_space",
	"kernelStruct.proc.struct_size",
	"kernelSymbol.allproc",
};

static uint32_t read_le32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static bool pread_exact(int fd, void *buffer, size_t length, off_t offset)
{
	unsigned char *out = (unsigned char *)buffer;
	size_t done = 0;
	while (done < length) {
		ssize_t count = pread(fd, out + done, length - done,
		                     offset + (off_t)done);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return false;
		done += (size_t)count;
	}
	return true;
}

static bool sha256_init(Sha256Context *ctx)
{
#if defined(__APPLE__)
	return CC_SHA256_Init(&ctx->context) == 1;
#else
	ctx->context = EVP_MD_CTX_new();
	return ctx->context != NULL &&
	       EVP_DigestInit_ex(ctx->context, EVP_sha256(), NULL) == 1;
#endif
}

static bool sha256_update(Sha256Context *ctx, const void *data, size_t length)
{
#if defined(__APPLE__)
	return CC_SHA256_Update(&ctx->context, data, (CC_LONG)length) == 1;
#else
	return EVP_DigestUpdate(ctx->context, data, length) == 1;
#endif
}

static bool sha256_final(Sha256Context *ctx, unsigned char digest[32])
{
#if defined(__APPLE__)
	return CC_SHA256_Final(digest, &ctx->context) == 1;
#else
	unsigned int length = 0;
	bool ok = EVP_DigestFinal_ex(ctx->context, digest, &length) == 1 &&
	          length == 32U;
	EVP_MD_CTX_free(ctx->context);
	ctx->context = NULL;
	return ok;
#endif
}

static bool sha256_fd(int fd, char output[65])
{
	unsigned char buffer[HASH_BUFFER_SIZE];
	unsigned char digest[32];
	Sha256Context ctx;
	if (!sha256_init(&ctx))
		return false;
	off_t offset = 0;
	for (;;) {
		ssize_t count = pread(fd, buffer, sizeof(buffer), offset);
		if (count < 0 && errno == EINTR)
			continue;
		if (count < 0) {
#if !defined(__APPLE__)
			EVP_MD_CTX_free(ctx.context);
#endif
			return false;
		}
		if (count == 0)
			break;
		if (!sha256_update(&ctx, buffer, (size_t)count)) {
#if !defined(__APPLE__)
			EVP_MD_CTX_free(ctx.context);
#endif
			return false;
		}
		offset += (off_t)count;
	}
	if (!sha256_final(&ctx, digest))
		return false;
	for (size_t i = 0; i < sizeof(digest); i++)
		snprintf(output + (i * 2U), 3U, "%02x", digest[i]);
	output[64] = '\0';
	return true;
}

static bool read_input_info(int fd, const struct stat *st, InputInfo *info,
	                        char *error, size_t error_size)
{
	unsigned char header[MACH_HEADER_64_SIZE];
	if (st->st_size < (off_t)sizeof(header) ||
	    !pread_exact(fd, header, sizeof(header), 0)) {
		snprintf(error, error_size, "file is shorter than a Mach-O 64-bit header");
		return false;
	}
	if (read_le32(header) != MH_MAGIC_64_VALUE) {
		snprintf(error, error_size, "input is not little-endian Mach-O 64-bit");
		return false;
	}
	uint32_t file_type = read_le32(header + 12);
	if (file_type != MH_FILESET_VALUE) {
		snprintf(error, error_size, "input Mach-O filetype is 0x%08" PRIx32
		         ", expected MH_FILESET (12)", file_type);
		return false;
	}
	uint32_t ncmds = read_le32(header + 16);
	uint32_t sizeofcmds = read_le32(header + 20);
	uint64_t commands_end = (uint64_t)MACH_HEADER_64_SIZE + sizeofcmds;
	if (commands_end > (uint64_t)st->st_size || ncmds > sizeofcmds / 8U) {
		snprintf(error, error_size, "Mach-O load-command bounds are invalid");
		return false;
	}

	uint32_t cpu_type = read_le32(header + 4);
	uint32_t cpu_subtype = read_le32(header + 8);
	bool found_uuid = false;
	uint64_t offset = MACH_HEADER_64_SIZE;
	for (uint32_t i = 0; i < ncmds; i++) {
		unsigned char command[UUID_LOAD_COMMAND_SIZE];
		if (offset + 8U > commands_end ||
		    !pread_exact(fd, command, 8U, (off_t)offset)) {
			snprintf(error, error_size, "truncated Mach-O load command");
			return false;
		}
		uint32_t cmd = read_le32(command);
		uint32_t cmdsize = read_le32(command + 4);
		if (cmdsize < 8U || offset + cmdsize > commands_end) {
			snprintf(error, error_size, "invalid Mach-O load-command size");
			return false;
		}
		if (cmd == LC_UUID_VALUE) {
			if (cmdsize < UUID_LOAD_COMMAND_SIZE ||
			    !pread_exact(fd, command, UUID_LOAD_COMMAND_SIZE,
			                 (off_t)offset)) {
				snprintf(error, error_size, "invalid LC_UUID command");
				return false;
			}
			for (size_t j = 0; j < 16U; j++)
				snprintf(info->uuid + j * 2U, 3U, "%02x", command[8U + j]);
			info->uuid[32] = '\0';
			found_uuid = true;
		}
		offset += cmdsize;
	}
	if (!found_uuid) {
		snprintf(error, error_size, "Mach-O LC_UUID command is missing");
		return false;
	}
	info->cpu_type = cpu_type;
	info->cpu_subtype = cpu_subtype;
	info->size = (uint64_t)st->st_size;
	if (!sha256_fd(fd, info->sha256)) {
		snprintf(error, error_size, "could not compute input SHA-256");
		return false;
	}
	return true;
}

static void json_string(const char *text)
{
	putchar('"');
	if (text != NULL) {
		for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
			switch (*p) {
			case '"': fputs("\\\"", stdout); break;
			case '\\': fputs("\\\\", stdout); break;
		case '\b': fputs("\\b", stdout); break;
		case '\f': fputs("\\f", stdout); break;
		case '\n': fputs("\\n", stdout); break;
		case '\r': fputs("\\r", stdout); break;
		case '\t': fputs("\\t", stdout); break;
		default:
			if (*p < 0x20U)
				printf("\\u%04x", *p);
			else
				putchar(*p);
			break;
			}
		}
	}
	putchar('"');
}

static const char *architecture_name(uint32_t cpu_type, uint32_t cpu_subtype)
{
	if (cpu_type == UINT32_C(0x0100000c)) {
		if ((cpu_subtype & UINT32_C(0x00ffffff)) == 2U)
			return "arm64e";
		if ((cpu_subtype & UINT32_C(0x00ffffff)) == 0U)
			return "arm64";
	}
	return "unknown";
}

static bool same_snapshot(const struct stat *a, const struct stat *b)
{
	/* Keep this portable across Apple SDK stat layouts. File contents are
	 * independently SHA-256 checked before and after the XPF call. */
	return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
	       a->st_size == b->st_size;
}

static void print_report(const char *path, const InputInfo *input,
	                     const char *xpf_start_status,
	                     const char *xpf_start_error,
	                     const char *status, const char *error,
	                     bool unchanged,
	                     const Metric metrics[4])
{
	printf("{\"schema\":\"xpf-preflight/1\",\"tool_version\":");
	json_string(XPF_PREFLIGHT_VERSION);
	printf(",\"source_commit\":");
	json_string(XPF_PREFLIGHT_SOURCE_COMMIT);
	printf(",\"libxpf_sha256\":");
	json_string(XPF_ARCHIVE_SHA256);
	printf(",\"expected_target\":");
	json_string(EXPECTED_TARGET);
	printf(",\"expected_input_sha256\":");
	json_string(XPF_EXPECTED_INPUT_SHA256);
	printf(",\"input\":{\"path\":");
	json_string(path);
	printf(",\"size\":");
	if (input->size != 0U)
		printf("%" PRIu64, input->size);
	else
		fputs("null", stdout);
	printf(",\"sha256\":");
	if (input->sha256[0] != '\0')
		json_string(input->sha256);
	else
		fputs("null", stdout);
	printf(",\"mach_o_filetype\":%s", input->size ? "\"MH_FILESET\"" : "null");
	printf(",\"architecture\":");
	if (input->size != 0U)
		json_string(architecture_name(input->cpu_type, input->cpu_subtype));
	else
		fputs("null", stdout);
	printf(",\"cpu_type\":");
	if (input->size != 0U)
		printf("%" PRIu32, input->cpu_type);
	else
		fputs("null", stdout);
	printf(",\"cpu_subtype\":");
	if (input->size != 0U)
		printf("%" PRIu32, input->cpu_subtype);
	else
		fputs("null", stdout);
	printf(",\"uuid\":");
	if (input->uuid[0] != '\0')
		json_string(input->uuid);
	else
		fputs("null", stdout);
	printf("},\"xpf_start\":{\"status\":");
	json_string(xpf_start_status);
	printf(",\"error\":");
	if (xpf_start_error != NULL && xpf_start_error[0] != '\0')
		json_string(xpf_start_error);
	else
		fputs("null", stdout);
	printf("},\"metrics\":{");
	for (size_t i = 0; i < 4U; i++) {
		if (i != 0U)
			putchar(',');
		json_string(metrics[i].name);
		printf(":{\"status\":\"%s\",\"value_hex\":",
		       metrics[i].resolved ? "resolved" :
		       (strcmp(xpf_start_status, "ok") == 0 ?
		        "unresolved" : "not_run"));
		if (metrics[i].resolved) {
			printf("\"0x%016" PRIx64 "\",\"value_dec\":%" PRIu64,
			       metrics[i].value, metrics[i].value);
		} else {
			fputs("null,\"value_dec\":null", stdout);
		}
		printf(",\"error\":");
		if (metrics[i].error[0] != '\0')
			json_string(metrics[i].error);
		else
			fputs("null", stdout);
		putchar('}');
	}
	printf("},\"input_unchanged\":%s,\"status\":", unchanged ? "true" : "false");
	json_string(status);
	printf(",\"error\":");
	if (error != NULL && error[0] != '\0')
		json_string(error);
	else
		fputs("null", stdout);
	fputs("}\n", stdout);
}

static void copy_xpf_error(char *destination, size_t size, const char *fallback)
{
	const char *error = xpf_get_error();
	snprintf(destination, size, "%s", error != NULL ? error : fallback);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <kernelcache.decompressed>\n", argv[0]);
		return 64;
	}

	InputInfo input = {0};
	Metric metrics[4] = {0};
	for (size_t i = 0; i < 4U; i++)
		metrics[i].name = metric_names[i];
	char error[256] = {0};
	char xpf_start_error[256] = {0};
	char after_hash[65] = {0};
	struct stat path_before = {0}, before = {0}, after = {0}, path_after = {0};
	const char *xpf_start_status = "not_run";
	bool unchanged = false;
	if (lstat(argv[1], &path_before) != 0 || !S_ISREG(path_before.st_mode)) {
		snprintf(error, sizeof(error), "input path is not a regular non-symlink file");
		print_report(argv[1], &input, xpf_start_status, NULL,
		             "input_error", error, false, metrics);
		return 2;
	}
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		snprintf(error, sizeof(error), "open read-only failed: %s", strerror(errno));
		print_report(argv[1], &input, xpf_start_status, NULL,
		             "input_error", error, false, metrics);
		return 2;
	}
	if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
	    !same_snapshot(&path_before, &before)) {
		snprintf(error, sizeof(error), "opened input differs from regular file path inspected before open");
		close(fd);
		print_report(argv[1], &input, xpf_start_status, NULL,
		             "input_error", error, false, metrics);
		return 2;
	}
	if (!read_input_info(fd, &before, &input, error, sizeof(error))) {
		close(fd);
		print_report(argv[1], &input, xpf_start_status, NULL,
		             "input_error", error, false, metrics);
		return 2;
	}
	if (strcmp(input.sha256, XPF_EXPECTED_INPUT_SHA256) != 0) {
		snprintf(error, sizeof(error), "input SHA-256 does not match the approved 21D61 kernelcache copy");
		close(fd);
		print_report(argv[1], &input, xpf_start_status, NULL,
		             "input_error", error, false, metrics);
		return 2;
	}

	int start_result = xpf_start_with_kernel_path(argv[1]);
	bool started = start_result == 0;
	xpf_start_status = started ? "ok" : "failed";
	if (!started) {
		copy_xpf_error(xpf_start_error, sizeof(xpf_start_error),
		               "xpf_start_with_kernel_path failed");
		snprintf(error, sizeof(error), "%s", xpf_start_error);
	} else {
		/* Keep the four requested finder calls explicit and auditable. */
		metrics[0].value = xpf_item_resolve("kernelConstant.T1SZ_BOOT");
		metrics[1].value = xpf_item_resolve("kernelStruct.task.itk_space");
		metrics[2].value = xpf_item_resolve("kernelStruct.proc.struct_size");
		metrics[3].value = xpf_item_resolve("kernelSymbol.allproc");
		for (size_t i = 0; i < 4U; i++) {
			metrics[i].resolved = metrics[i].value != 0U;
			if (!metrics[i].resolved)
				copy_xpf_error(metrics[i].error, sizeof(metrics[i].error),
				               "finder returned zero");
		}
		xpf_stop();
	}

	if (fstat(fd, &after) == 0 && same_snapshot(&before, &after) &&
	    same_snapshot(&path_before, &after) &&
	    lstat(argv[1], &path_after) == 0 && same_snapshot(&before, &path_after) &&
	    sha256_fd(fd, after_hash) && strcmp(input.sha256, after_hash) == 0) {
		unchanged = true;
	} else if (error[0] == '\0') {
		snprintf(error, sizeof(error), "input file changed during preflight or could not be rechecked");
	}
	close(fd);

	bool metrics_ok = true;
	for (size_t i = 0; i < 4U; i++)
		metrics_ok = metrics_ok && metrics[i].resolved;
	const char *status = started && metrics_ok && unchanged ? "ok" : "error";
	if (error[0] == '\0' && !metrics_ok)
		snprintf(error, sizeof(error), "one or more XPF finders returned zero");
	print_report(argv[1], &input, xpf_start_status, xpf_start_error,
	             status, error[0] != '\0' ? error : NULL, unchanged, metrics);
	return strcmp(status, "ok") == 0 ? 0 : 3;
}
