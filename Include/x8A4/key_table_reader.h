#ifndef X8A4_KEY_TABLE_READER_H
#define X8A4_KEY_TABLE_READER_H

#include <stddef.h>
#include <stdint.h>
#include <x8A4/key_bounds.h>

/* Return zero only when a full requested read succeeded. */
typedef int (*x8A4_key_reader_fn)(uint64_t address, void *output, size_t size);

/* This is the production key-record reader, also invoked by the host's ASan
 * tests using a mock kernel reader. No kernel or NVRAM write functions. */
static inline int x8A4_read_accel_records(
    uint64_t kernel_base, void *records, uint32_t count, size_t record_size,
    x8A4_key_reader_fn reader) {
  if (!reader || !records || !kernel_base || record_size != 52 ||
      !x8A4_accel_count_valid(count))
    return -1;

  for (uint32_t i = 0; i < count; ++i) {
    size_t byte_offset = 0;
    if (!x8A4_accel_offset(count, i, record_size, &byte_offset) ||
        kernel_base > UINT64_MAX - (uint64_t)byte_offset ||
        reader(kernel_base + (uint64_t)byte_offset,
               (uint8_t *)records + byte_offset, record_size) != 0)
      return -1;
  }
  return 0;
}

#endif
