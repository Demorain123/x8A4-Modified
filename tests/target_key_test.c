#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <x8A4/target_key.h>

struct mock {
  struct x8A4_target_key_record records[4];
  uint64_t base;
  int reads;
  int fail_on_read;
};

static int mock_kread(uint64_t address, void *dst, size_t bytes, void *ctx) {
  struct mock *m = ctx;
  ++m->reads;
  if (m->fail_on_read == m->reads || address < m->base ||
      bytes != sizeof(m->records[0])) return -1;
  uint64_t diff = address - m->base;
  if (diff % sizeof(m->records[0]) ||
      diff >= sizeof(m->records)) return -1;
  memcpy(dst, (const uint8_t *)m->records + (size_t)diff, bytes);
  return 0;
}

int main(void) {
  const uint64_t base = UINT64_C(0xfffffff007100000);
  struct mock m = {.base=base};
  m.records[0].key_id = 0x111;
  m.records[1].key_id = 0x8A3;
  m.records[1].generated = 1;
  m.records[1].key_sz = 16;
  m.records[1].key[0] = 0x12345678;
  m.records[2].key_id = 0x8A4;
  m.records[2].generated = 1;
  m.records[2].key_sz = 128;
  struct x8A4_target_key_record out;
  uint32_t idx;

  assert(!x8A4_scan_target_key(base, 4, 0x8A3, &out, &idx, mock_kread, &m));
  assert(idx == 1 && m.reads == 2 && out.key[0] == 0x12345678);
  m.reads = 0;
  assert(!x8A4_scan_target_key(base, 4, 0x8A4, &out, &idx, mock_kread, &m));
  assert(idx == 2 && m.reads == 3);

  m.records[1].generated = 0;
  m.reads = 0;
  assert(x8A4_scan_target_key(base, 4, 0x8A3, &out, &idx, mock_kread, &m) == -5);
  assert(idx == UINT32_MAX && out.key_id == 0 && out.key[0] == 0);
  m.records[1].generated = 1;

  m.reads = 0; m.fail_on_read = 2;
  assert(x8A4_scan_target_key(base, 4, 0x8A3, &out, &idx, mock_kread, &m) == -4);
  assert(m.reads == 2 && idx == UINT32_MAX && out.key_id == 0);
  m.fail_on_read = 0;

  assert(x8A4_scan_target_key(base, 0, 0x8A3, &out, &idx, mock_kread, &m) == -2);
  assert(x8A4_scan_target_key(base, 129, 0x8A3, &out, &idx, mock_kread, &m) == -2);
  assert(x8A4_scan_target_key(0, 4, 0x8A3, &out, &idx, mock_kread, &m) == -2);
  assert(x8A4_scan_target_key(base, 4, 0x999, &out, &idx, mock_kread, &m) == -2);
  assert(x8A4_scan_target_key(UINT64_MAX - 12, 4, 0x8A3,
                              &out, &idx, mock_kread, &m) != 0);
  m.records[1].key_id = 0x111;
  assert(x8A4_scan_target_key(base, 4, 0x8A3, &out, &idx, mock_kread, &m) == -1);
  assert(idx == UINT32_MAX && out.key_id == 0);
  puts("PASS: targeted key reads, early stop, missing/invalid keys and read failure");
  return 0;
}
