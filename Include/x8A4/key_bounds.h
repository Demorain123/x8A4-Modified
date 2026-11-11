#ifndef X8A4_KEY_BOUNDS_H
#define X8A4_KEY_BOUNDS_H

#include <stddef.h>
#include <stdint.h>

/* Conservative ceiling until the target kernel layout has been audited. */
#define X8A4_MAX_ACCEL_KEYS 128U

static inline int x8A4_accel_count_valid(uint32_t count) {
  return count > 0 && count <= X8A4_MAX_ACCEL_KEYS;
}

/* Kernel pointers are byte addresses; this is a BYTE offset, not an index
 * to add to a struct pointer. Reject invalid counts and size overflows. */
static inline int x8A4_accel_offset(uint32_t count, uint32_t index,
                                   size_t record_size, size_t *out_offset) {
  if (!out_offset || !record_size || !x8A4_accel_count_valid(count) ||
      index >= count || (size_t)index > SIZE_MAX / record_size)
    return 0;
  *out_offset = (size_t)index * record_size;
  return 1;
}

/* Check the WHOLE [address, address + length) kernel read interval.
 * Checking only the record's starting address would miss u64 wraparound.
 * The exclusive upper bound is intentionally conservative.
 */
static inline int x8A4_kernel_read_span(uint64_t base, uint64_t offset,
                                       uint64_t read_length,
                                       uint64_t *out_address) {
  if (out_address) *out_address = 0;
  if (!out_address || !base || !read_length ||
      offset > UINT64_MAX - base)
    return 0;
  uint64_t address = base + offset;
  if (read_length > UINT64_MAX - address)
    return 0;
  *out_address = address;
  return 1;
}

#endif
