#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <x8A4/key_table_reader.h>

enum { TEST_COUNT = 3, TEST_RECORD_SIZE = 52 };
#define TEST_BASE UINT64_C(0x10000)

static uint8_t kernel_bytes[TEST_COUNT * TEST_RECORD_SIZE];
static int call_count = 0, fail_at_call = -1;
static int span_calls = 0;
static int permissive_reader(uint64_t addr, void *out, size_t size) {
  (void)addr; (void)out; (void)size;
  ++span_calls;
  return 0;
}

static int mock_kread(uint64_t addr, void *out, size_t size) {
  int call = call_count++;
  if (call == fail_at_call) return -1;
  if (addr < TEST_BASE || size != TEST_RECORD_SIZE ||
      (uint64_t)(sizeof(kernel_bytes) - size) < addr - TEST_BASE)
    return -1;
  memcpy(out, kernel_bytes + (addr - TEST_BASE), size);
  return 0;
}

int main(void) {
  for (size_t i = 0; i < sizeof(kernel_bytes); ++i)
    kernel_bytes[i] = (uint8_t)((i * 43 + 17) & 255);

  struct {
    uint8_t before[16];
    uint8_t records[TEST_COUNT * TEST_RECORD_SIZE];
    uint8_t after[16];
  } result = {0};
  memset(result.before, 0xBC, sizeof(result.before));
  memset(result.after, 0xAC, sizeof(result.after));

  assert(x8A4_read_accel_records(TEST_BASE, result.records, TEST_COUNT,
                                 TEST_RECORD_SIZE, mock_kread) == 0);
  assert(call_count == TEST_COUNT);
  assert(memcmp(result.records, kernel_bytes, sizeof(kernel_bytes)) == 0);
  for (size_t i = 0; i < sizeof(result.before); i++)
    assert(result.before[i] == 0xBC && result.after[i] == 0xAC);

  assert(x8A4_read_accel_records(TEST_BASE, NULL, 3, 52, mock_kread) != 0);
  assert(x8A4_read_accel_records(0, result.records, 3, 52, mock_kread) != 0);
  assert(x8A4_read_accel_records(TEST_BASE, result.records, 0, 52, mock_kread) != 0);
  assert(x8A4_read_accel_records(TEST_BASE, result.records, 129, 52, mock_kread) != 0);
  assert(x8A4_read_accel_records(TEST_BASE, result.records, 3, 2704, mock_kread) != 0);
  assert(x8A4_read_accel_records(TEST_BASE, result.records, 3, 52, NULL) != 0);
  assert(x8A4_read_accel_records(UINT64_MAX - 20, result.records, 3,
                                 52, mock_kread) != 0);

  call_count = 0;
  assert(x8A4_read_accel_records(UINT64_MAX - 15, result.records,
                                 1, 52, mock_kread) != 0);
  assert(call_count == 0);
  span_calls = 0;
  assert(x8A4_read_accel_records(UINT64_MAX - 60, result.records,
                                 2, 52, permissive_reader) != 0);
  assert(span_calls == 1);
  span_calls = 0;
  assert(x8A4_read_accel_records(UINT64_MAX - 52, result.records,
                                 1, 52, permissive_reader) == 0);
  assert(span_calls == 1);
  call_count = 0; fail_at_call = 1;
  assert(x8A4_read_accel_records(TEST_BASE, result.records, 3,
                                 52, mock_kread) != 0);
  assert(call_count == 2);
  puts("PASS: shared production loop, address bounds, 52-byte stride, "
       "failure injection and canaries");
  return 0;
}
