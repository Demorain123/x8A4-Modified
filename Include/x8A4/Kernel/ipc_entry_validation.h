/*
 * Pure IPC name, entry-bound, generation, and capability checks.
 *
 * The only concrete layout accepted here is a reference fixture derived from
 * XNU xnu-10002.81.5. It is deliberately NOT marked as the exact 21D61
 * layout. Production code must not opt into it without target-level evidence.
 * This header never dereferences kernel memory and provides no SMR/PAC safety.
 */
#ifndef X8A4_IPC_ENTRY_VALIDATION_H
#define X8A4_IPC_ENTRY_VALIDATION_H

#include <stdbool.h>
#include <stdint.h>

#define X8A4_MACH_PORT_NULL UINT32_C(0)
#define X8A4_MACH_PORT_DEAD UINT32_MAX

#define X8A4_IPC_ENTRY_SIZE_XNU_10002_81_5 UINT32_C(0x18)
#define X8A4_IPC_ENTRY_OBJECT_OFFSET_XNU_10002_81_5 UINT32_C(0x00)
#define X8A4_IPC_ENTRY_BITS_OFFSET_XNU_10002_81_5 UINT32_C(0x08)
#define X8A4_IPC_ENTRY_TYPE_MASK_XNU_10002_81_5 UINT32_C(0x001f0000)
#define X8A4_IPC_ENTRY_GENERATION_MASK_XNU_10002_81_5 UINT32_C(0xff000000)
#define X8A4_IPC_ENTRY_TYPE_SHIFT_XNU_10002_81_5 16U
#define X8A4_IPC_ENTRY_GENERATION_SHIFT_XNU_10002_81_5 24U
#define X8A4_IPC_ENTRY_KNOWN_TYPE_BITS_XNU_10002_81_5 UINT32_C(0x1f)

enum x8a4_ipc_layout_id {
  X8A4_IPC_LAYOUT_UNVERIFIED = 0,
  X8A4_IPC_LAYOUT_XNU_10002_81_5_REFERENCE = 1
};

enum x8a4_ipc_validation_status {
  X8A4_IPC_VALID = 0,
  X8A4_IPC_INVALID_ARGUMENT,
  X8A4_IPC_INVALID_NAME,
  X8A4_IPC_INDEX_ZERO,
  X8A4_IPC_UNKNOWN_CAPACITY,
  X8A4_IPC_UNSUPPORTED_LAYOUT,
  X8A4_IPC_INDEX_OUT_OF_BOUNDS,
  X8A4_IPC_ADDRESS_OVERFLOW,
  X8A4_IPC_GENERATION_MISMATCH,
  X8A4_IPC_TYPE_NONE,
  /* Defensive for future layouts; unreachable with the current 5-bit mask. */
  X8A4_IPC_INVALID_TYPE_BITS,
  X8A4_IPC_TYPE_MISMATCH
};

struct x8a4_ipc_entry_layout {
  enum x8a4_ipc_layout_id id;
  uint32_t entry_size;
  uint32_t object_offset;
  uint32_t bits_offset;
  uint32_t type_mask;
  uint32_t generation_mask;
  uint32_t type_shift;
  uint32_t generation_shift;
  uint32_t known_type_bits;
};

struct x8a4_ipc_entry_addresses {
  uint32_t index;
  uint64_t entry;
  uint64_t object;
  uint64_t bits;
};

/* Mach port names encode a 24-bit index above an 8-bit generation. */
static inline enum x8a4_ipc_validation_status
x8a4_ipc_port_name_index(uint32_t name, uint32_t *index_out) {
  if (index_out == 0) {
    return X8A4_IPC_INVALID_ARGUMENT;
  }
  *index_out = 0;
  if (name == X8A4_MACH_PORT_NULL || name == X8A4_MACH_PORT_DEAD) {
    return X8A4_IPC_INVALID_NAME;
  }
  const uint32_t index = name >> 8;
  if (index == 0) {
    return X8A4_IPC_INDEX_ZERO;
  }
  *index_out = index;
  return X8A4_IPC_VALID;
}

static inline bool
x8a4_ipc_layout_is_supported(const struct x8a4_ipc_entry_layout *layout) {
  return layout != 0 &&
         layout->id == X8A4_IPC_LAYOUT_XNU_10002_81_5_REFERENCE &&
         layout->entry_size == X8A4_IPC_ENTRY_SIZE_XNU_10002_81_5 &&
         layout->object_offset == X8A4_IPC_ENTRY_OBJECT_OFFSET_XNU_10002_81_5 &&
         layout->bits_offset == X8A4_IPC_ENTRY_BITS_OFFSET_XNU_10002_81_5 &&
         layout->type_mask == X8A4_IPC_ENTRY_TYPE_MASK_XNU_10002_81_5 &&
         layout->generation_mask == X8A4_IPC_ENTRY_GENERATION_MASK_XNU_10002_81_5 &&
         layout->type_shift == X8A4_IPC_ENTRY_TYPE_SHIFT_XNU_10002_81_5 &&
         layout->generation_shift == X8A4_IPC_ENTRY_GENERATION_SHIFT_XNU_10002_81_5 &&
         layout->known_type_bits == X8A4_IPC_ENTRY_KNOWN_TYPE_BITS_XNU_10002_81_5;
}

/* Checked arithmetic is separate so overflow cases can be tested directly. */
static inline enum x8a4_ipc_validation_status
x8a4_ipc_entry_calculate_addresses(
    uint64_t table_base, uint64_t index,
    const struct x8a4_ipc_entry_layout *layout,
    struct x8a4_ipc_entry_addresses *addresses) {
  if (addresses == 0) {
    return X8A4_IPC_INVALID_ARGUMENT;
  }
  /* Every failure leaves the complete output record, including index, empty. */
  *addresses = (struct x8a4_ipc_entry_addresses){0};
  if (index == 0) {
    return X8A4_IPC_INDEX_ZERO;
  }
  if (!x8a4_ipc_layout_is_supported(layout) || table_base == 0) {
    return X8A4_IPC_UNSUPPORTED_LAYOUT;
  }
  if (index > UINT64_MAX / (uint64_t)layout->entry_size) {
    return X8A4_IPC_ADDRESS_OVERFLOW;
  }
  const uint64_t delta = index * (uint64_t)layout->entry_size;
  if (table_base > UINT64_MAX - delta) {
    return X8A4_IPC_ADDRESS_OVERFLOW;
  }
  const uint64_t entry = table_base + delta;
  if ((uint64_t)layout->object_offset > UINT64_MAX - entry ||
      (uint64_t)layout->bits_offset > UINT64_MAX - entry) {
    return X8A4_IPC_ADDRESS_OVERFLOW;
  }
  if (layout->object_offset > layout->entry_size ||
      sizeof(uint64_t) > layout->entry_size - layout->object_offset ||
      layout->bits_offset > layout->entry_size ||
      sizeof(uint32_t) > layout->entry_size - layout->bits_offset) {
    return X8A4_IPC_UNSUPPORTED_LAYOUT;
  }
  addresses->entry = entry;
  addresses->object = entry + layout->object_offset;
  addresses->bits = entry + layout->bits_offset;
  return X8A4_IPC_VALID;
}

/*
 * Validate bounds and compute addresses before any caller reads an entry.
 * table_capacity is an entry count that includes reserved slot zero.
 */
static inline enum x8a4_ipc_validation_status
x8a4_ipc_entry_plan(uint32_t name,
                    const struct x8a4_ipc_entry_layout *layout,
                    bool capacity_known, uint64_t table_capacity,
                    uint64_t table_base,
                    struct x8a4_ipc_entry_addresses *addresses) {
  uint32_t index = 0;
  enum x8a4_ipc_validation_status status =
      x8a4_ipc_port_name_index(name, &index);
  if (status != X8A4_IPC_VALID) {
    if (addresses != 0) {
      *addresses = (struct x8a4_ipc_entry_addresses){0};
    }
    return status;
  }
  if (addresses == 0) {
    return X8A4_IPC_INVALID_ARGUMENT;
  }
  *addresses = (struct x8a4_ipc_entry_addresses){0};
  if (!x8a4_ipc_layout_is_supported(layout)) {
    return X8A4_IPC_UNSUPPORTED_LAYOUT;
  }
  if (!capacity_known) {
    return X8A4_IPC_UNKNOWN_CAPACITY;
  }
  if ((uint64_t)index >= table_capacity) {
    return X8A4_IPC_INDEX_OUT_OF_BOUNDS;
  }
  status = x8a4_ipc_entry_calculate_addresses(table_base, index, layout, addresses);
  if (status != X8A4_IPC_VALID) {
    *addresses = (struct x8a4_ipc_entry_addresses){0};
    return status;
  }
  addresses->index = index;
  return X8A4_IPC_VALID;
}

/*
 * Check a previously read ie_bits snapshot. This validates only its encoded
 * generation and capability bits; it cannot make the read race-free.
 * required_type_bits uses the unshifted 5-bit XNU capability mask (zero means
 * any non-empty known capability).
 */
static inline enum x8a4_ipc_validation_status
x8a4_ipc_entry_validate_bits(uint32_t name,
                             const struct x8a4_ipc_entry_layout *layout,
                             uint32_t entry_bits,
                             uint32_t required_type_bits,
                             uint32_t *type_out) {
  uint32_t index = 0;
  enum x8a4_ipc_validation_status status =
      x8a4_ipc_port_name_index(name, &index);
  (void)index;
  if (type_out != 0) {
    *type_out = 0;
  }
  if (status != X8A4_IPC_VALID) {
    return status;
  }
  if (!x8a4_ipc_layout_is_supported(layout) ||
      (required_type_bits & ~layout->known_type_bits) != 0) {
    return X8A4_IPC_UNSUPPORTED_LAYOUT;
  }
  const uint32_t expected_generation =
      (name & UINT32_C(0xff)) << layout->generation_shift;
  if ((entry_bits & layout->generation_mask) != expected_generation) {
    return X8A4_IPC_GENERATION_MISMATCH;
  }
  const uint32_t type =
      (entry_bits & layout->type_mask) >> layout->type_shift;
  if (type == 0) {
    return X8A4_IPC_TYPE_NONE;
  }
  /*
   * Unreachable for this reference layout: type_mask exposes exactly bits
   * 0..4 and known_type_bits is 0x1f. Keep this guard for any future
   * supported layout that widens the field or narrows its known-bit set.
   */
  if ((type & ~layout->known_type_bits) != 0) {
    return X8A4_IPC_INVALID_TYPE_BITS;
  }
  if ((type & required_type_bits) != required_type_bits) {
    return X8A4_IPC_TYPE_MISMATCH;
  }
  if (type_out != 0) {
    *type_out = type;
  }
  return X8A4_IPC_VALID;
}

#endif /* X8A4_IPC_ENTRY_VALIDATION_H */
