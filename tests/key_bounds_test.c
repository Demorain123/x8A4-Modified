#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <x8A4/key_bounds.h>

struct fake_key { uint32_t id; unsigned char payload[48]; };
_Static_assert(sizeof(struct fake_key) == 52, "Unexpected test record size");

int main(void) {
  size_t offset = 999;
  assert(!x8A4_accel_count_valid(0));
  assert(x8A4_accel_count_valid(1));
  assert(x8A4_accel_count_valid(128));
  assert(!x8A4_accel_count_valid(129));
  assert(!x8A4_accel_count_valid(UINT32_MAX));
  assert(!x8A4_accel_offset(0, 0, 52, &offset));
  assert(!x8A4_accel_offset(129, 0, 52, &offset));
  assert(!x8A4_accel_offset(3, 3, 52, &offset));
  assert(!x8A4_accel_offset(3, 1, 0, &offset));
  assert(!x8A4_accel_offset(3, 1, 52, NULL));
  assert(x8A4_accel_offset(3, 2, 52, &offset) && offset == 104);

  struct fake_key entries[3] = {{.id=0x111}, {.id=0x8A3}, {.id=0x8A4}};
  const unsigned char *bytes = (const unsigned char *)entries;
  for (uint32_t i=0; i<3; ++i) {
    assert(x8A4_accel_offset(3, i, sizeof(*entries), &offset));
    assert((const void *)(bytes+offset) == (const void *)&entries[i]);
  }
  assert(entries[1].id == 0x8A3 && entries[2].id == 0x8A4);
  puts("PASS: key table count, offset, and 52-byte stride tests");
  return 0;
}
