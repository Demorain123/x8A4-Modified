#ifndef X8A4_TARGET_KEY_H
#define X8A4_TARGET_KEY_H

/* Host-testable, bounded, read-only scanner for one accelerator key ID.
 * The callback is supplied by the platform layer; this header does not
 * import libkrw, initialize the kernel, or write device memory.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <x8A4/key_bounds.h>

struct x8A4_target_key_record {
  uint32_t generated, key_id, key_sz;
  uint32_t key[4], iv[4];
  uint32_t zero, pad;
};
_Static_assert(sizeof(struct x8A4_target_key_record) == 52,
               "Accelerator record layout is not 52 bytes");

typedef int (*x8A4_target_read_fn)(uint64_t, void *, size_t, void *);

/* 0 = found; negative values mean NOT FOUND / INVALID / READ ERROR.
 * out_record is zeroed on all failures. No heap allocations.
 */
static inline int x8A4_scan_target_key(
    uint64_t base, uint32_t count, uint32_t requested_id,
    struct x8A4_target_key_record *out_record, uint32_t *out_index,
    x8A4_target_read_fn read_one, void *context) {
  if (out_record) memset(out_record, 0, sizeof(*out_record));
  if (out_index) *out_index = UINT32_MAX;
  if (!out_record || !out_index || !read_one ||
      (requested_id != 0x8A3 && requested_id != 0x8A4) ||
      !base || !x8A4_accel_count_valid(count))
    return -2;

  for (uint32_t i = 0; i < count; ++i) {
    size_t offset = 0;
    uint64_t address = 0;
    if (!x8A4_accel_offset(count, i, sizeof(*out_record), &offset) ||
        !x8A4_kernel_read_span(base, (uint64_t)offset,
                              sizeof(*out_record), &address))
      return -3;
    struct x8A4_target_key_record entry = {0};
    if (read_one(address, &entry, sizeof(entry), context)) {
      memset(&entry, 0, sizeof(entry));
      return -4; /* fail closed: do not skip unreadable entries */
    }
    if (entry.key_id != requested_id) {
      memset(&entry, 0, sizeof(entry));
      continue;
    }
    if (entry.generated != 1 || (entry.key_sz != 16 && entry.key_sz != 128)) {
      memset(&entry, 0, sizeof(entry));
      return -5;
    }
    *out_record = entry;
    *out_index = i;
    memset(&entry, 0, sizeof(entry));
    return 0; /* never scan the rest of the table after a match */
  }
  return -1;
}

#endif
