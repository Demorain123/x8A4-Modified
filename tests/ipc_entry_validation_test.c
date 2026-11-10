#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include <x8A4/Kernel/ipc_entry_validation.h>

static const struct x8a4_ipc_entry_layout kReferenceLayout = {
    .id = X8A4_IPC_LAYOUT_XNU_10002_81_5_REFERENCE,
    .entry_size = X8A4_IPC_ENTRY_SIZE_XNU_10002_81_5,
    .object_offset = X8A4_IPC_ENTRY_OBJECT_OFFSET_XNU_10002_81_5,
    .bits_offset = X8A4_IPC_ENTRY_BITS_OFFSET_XNU_10002_81_5,
    .type_mask = X8A4_IPC_ENTRY_TYPE_MASK_XNU_10002_81_5,
    .generation_mask = X8A4_IPC_ENTRY_GENERATION_MASK_XNU_10002_81_5,
    .type_shift = X8A4_IPC_ENTRY_TYPE_SHIFT_XNU_10002_81_5,
    .generation_shift = X8A4_IPC_ENTRY_GENERATION_SHIFT_XNU_10002_81_5,
    .known_type_bits = X8A4_IPC_ENTRY_KNOWN_TYPE_BITS_XNU_10002_81_5,
};

static const uint32_t kPortName = (UINT32_C(7) << 8) | UINT32_C(0x42);
static const uint64_t kTableBase = UINT64_C(0xfffffe0001234000);

static uint32_t
entry_bits(uint32_t name, uint32_t capability_type) {
  return ((name & UINT32_C(0xff)) << X8A4_IPC_ENTRY_GENERATION_SHIFT_XNU_10002_81_5) |
         (capability_type << X8A4_IPC_ENTRY_TYPE_SHIFT_XNU_10002_81_5);
}

static void
assert_addresses_empty(const struct x8a4_ipc_entry_addresses *addresses) {
  assert(addresses->index == 0);
  assert(addresses->entry == 0);
  assert(addresses->object == 0);
  assert(addresses->bits == 0);
}

static void
seed_addresses(struct x8a4_ipc_entry_addresses *addresses) {
  *addresses = (struct x8a4_ipc_entry_addresses){
      .index = UINT32_C(0xfeed),
      .entry = UINT64_C(0xfeedface),
      .object = UINT64_C(0xdeadbeef),
      .bits = UINT64_C(0xcafebabe),
  };
}

int main(void) {
  struct x8a4_ipc_entry_addresses addresses = {0};
  uint32_t type = 0;

  /* Valid reference layout, bounded index, and representable entry addresses. */
  assert(x8a4_ipc_entry_plan(kPortName, &kReferenceLayout, true, 8,
                             kTableBase, &addresses) == X8A4_IPC_VALID);
  assert(addresses.index == 7);
  assert(addresses.entry == kTableBase + UINT64_C(7) * UINT64_C(0x18));
  assert(addresses.object == addresses.entry);
  assert(addresses.bits == addresses.entry + UINT64_C(8));
  assert(x8a4_ipc_entry_validate_bits(kPortName, &kReferenceLayout,
                                      entry_bits(kPortName, 1), 1,
                                      &type) == X8A4_IPC_VALID);
  assert(type == 1);

  /* Null/dead names and slot zero are rejected before planning a read. */
  assert(x8a4_ipc_port_name_index(X8A4_MACH_PORT_NULL, &type) ==
         X8A4_IPC_INVALID_NAME);
  assert(x8a4_ipc_port_name_index(X8A4_MACH_PORT_DEAD, &type) ==
         X8A4_IPC_INVALID_NAME);
  assert(x8a4_ipc_port_name_index(UINT32_C(0x00000042), &type) ==
         X8A4_IPC_INDEX_ZERO);
  seed_addresses(&addresses);
  assert(x8a4_ipc_entry_plan(UINT32_C(0x00000042), &kReferenceLayout, true,
                             8, kTableBase, &addresses) == X8A4_IPC_INDEX_ZERO);
  assert_addresses_empty(&addresses);

  /* Unknown capacity, unsupported layout, and an out-of-range index fail. */
  seed_addresses(&addresses);
  assert(x8a4_ipc_entry_plan(kPortName, &kReferenceLayout, false, 8,
                             kTableBase, &addresses) == X8A4_IPC_UNKNOWN_CAPACITY);
  assert_addresses_empty(&addresses);
  struct x8a4_ipc_entry_layout unverified = kReferenceLayout;
  unverified.id = X8A4_IPC_LAYOUT_UNVERIFIED;
  seed_addresses(&addresses);
  assert(x8a4_ipc_entry_plan(kPortName, &unverified, true, 8,
                             kTableBase, &addresses) == X8A4_IPC_UNSUPPORTED_LAYOUT);
  assert_addresses_empty(&addresses);
  struct x8a4_ipc_entry_layout malformed = kReferenceLayout;
  malformed.entry_size = UINT32_C(0x20);
  seed_addresses(&addresses);
  assert(x8a4_ipc_entry_plan(kPortName, &malformed, true, 8,
                             kTableBase, &addresses) == X8A4_IPC_UNSUPPORTED_LAYOUT);
  assert_addresses_empty(&addresses);
  seed_addresses(&addresses);
  assert(x8a4_ipc_entry_plan(kPortName, &kReferenceLayout, true, 7,
                             kTableBase, &addresses) == X8A4_IPC_INDEX_OUT_OF_BOUNDS);
  assert_addresses_empty(&addresses);

  /* Multiplication and base-plus-offset overflow are rejected. */
  seed_addresses(&addresses);
  assert(x8a4_ipc_entry_calculate_addresses(kTableBase, UINT64_MAX,
                                            &kReferenceLayout, &addresses) ==
         X8A4_IPC_ADDRESS_OVERFLOW);
  assert_addresses_empty(&addresses);
  seed_addresses(&addresses);
  assert(x8a4_ipc_entry_calculate_addresses(UINT64_MAX - UINT64_C(100), 7,
                                            &kReferenceLayout, &addresses) ==
         X8A4_IPC_ADDRESS_OVERFLOW);
  assert_addresses_empty(&addresses);
  seed_addresses(&addresses);
  assert(x8a4_ipc_entry_calculate_addresses(
             UINT64_MAX - UINT64_C(168), 7, &kReferenceLayout, &addresses) ==
         X8A4_IPC_ADDRESS_OVERFLOW);
  assert_addresses_empty(&addresses);
  seed_addresses(&addresses);
  assert(x8a4_ipc_entry_calculate_addresses(kTableBase, 0,
                                            &kReferenceLayout, &addresses) ==
         X8A4_IPC_INDEX_ZERO);
  assert_addresses_empty(&addresses);

  /* The reference's 5-bit type field cannot encode unknown type bits. */
  for (uint32_t type_bits = 0; type_bits <= UINT32_C(0x1f); ++type_bits) {
    const enum x8a4_ipc_validation_status status =
        x8a4_ipc_entry_validate_bits(kPortName, &kReferenceLayout,
                                    entry_bits(kPortName, type_bits), 0, NULL);
    assert(status != X8A4_IPC_INVALID_TYPE_BITS);
  }

  /* Generation mismatch, empty rights, and required-capability mismatch. */
  assert(x8a4_ipc_entry_validate_bits(kPortName, &kReferenceLayout,
                                     entry_bits(kPortName + UINT32_C(1), 1),
                                     1, &type) == X8A4_IPC_GENERATION_MISMATCH);
  assert(type == 0);
  assert(x8a4_ipc_entry_validate_bits(kPortName, &kReferenceLayout,
                                     entry_bits(kPortName, 0), 0,
                                     &type) == X8A4_IPC_TYPE_NONE);
  assert(x8a4_ipc_entry_validate_bits(kPortName, &kReferenceLayout,
                                     entry_bits(kPortName, 2), 1,
                                     &type) == X8A4_IPC_TYPE_MISMATCH);
  assert(x8a4_ipc_entry_validate_bits(kPortName, &kReferenceLayout,
                                     entry_bits(kPortName, 1), 0x20,
                                     &type) == X8A4_IPC_UNSUPPORTED_LAYOUT);

  puts("PASS: IPC entry name/bounds/generation/type fixtures (reference layout only)");
  return 0;
}
