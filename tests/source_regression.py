"""Regression checks for the currently targeted x8A4 key paths.

This checks source-level invariants, not Mach-O instruction safety or M1 compatibility.
"""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
src = (root / "x8A4.c").read_text()
cli = (root / "x8A4_CLI.c").read_text()
live = src.split("\n#if 0", 1)[0]

bad = [
    "keys + (struct_size * i)",
    "out_keys + (struct_size * i)",
    "%08X%08X%08X%08X%",
]
for pattern in bad:
    assert pattern not in live, f"Unsafe pattern remains: {pattern}"

for expected in (
    "x8A4_accel_count_valid(count)",
    "keys[i].key_id == 0x8A3",
    "keys[i].key_id == 0x8A4",
):
    assert expected in live, f"Expected safety check absent: {expected}"

for forbidden in (
    "x8A4_cli_set_cryptex_seed",
    "x8A4_cli_set_apnonce_generator",
    "x8A4_cli_clear_apnonce_generator",
    '"set-cryptex-nonce"',
    '"set-apnonce-generator"',
    '"clear-apnonce-generator"',
):
    assert forbidden not in cli, f"Mutation API exposed by CLI: {forbidden}"

assert "(entry->key_sz != 16 && entry->key_sz != 128)" in src
assert "X8A4_ENABLE_LIVE_KEY_READ" in cli
assert "live kernel key reading disabled" in cli
# The CLI must use the single-key stack scanner, not allocate the entire
# kernel accelerator table or put secret buffers into the legacy GC lists.
start = src.index("int x8A4_cli_get_accel_keys(uint32_t chosen_key) {")
end = src.index("\n/**\n * @brief           CLI get nonce-seeds", start)
key_cli = src[start:end]
assert "x8A4_lookup_target_key(chosen_key, &key, &index)" in key_cli
assert "x8A4_get_ioaesaccelkeys(" not in key_cli
assert "calloc(" not in key_cli
assert "gc_cached" not in key_cli and "gc_d_cached" not in key_cli
assert "x8A4_scan_target_key(" in src
assert "x8A4_accel_count_valid(count)" in src
assert "kobj > UINT64_MAX -" in src

for path, forbidden in {
    "Kernel/nvram.c": ("kwrite(", "set_nvram_entry_bytes("),
    "Kernel/kernel.c": ("IOConnectCallStructMethod(", "io_generate_apnonce(", "io_clear_apnonce("),
    "Registry/registry.c": ("IORegistryEntrySetCFProperty(", "int set_nvram_entry("),
    "Services/services.c": ("get_apple_mobile_ap_nonce_service(",),
}.items():
    current = (root / path).read_text()
    for marker in forbidden:
        assert marker not in current, f"Forbidden mutation implementation: {path}: {marker}"

object_file = (root / "Kernel/osobject.c").read_text()
assert "&dict_size, sizeof(dict_size)" in object_file
assert "key_len >= PATH_MAX" in object_file
assert "char key_string[PATH_MAX] = {0}" in object_file
offsets = (root / "Kernel/offsets.c").read_text()
assert "valid_resolved_offset" in offsets
assert "return -1;" in offsets
kernel = (root / "Kernel/kernel.c").read_text()
assert "get_boot_manifest_hash_len()" in kernel
assert "Preboot kernelcache path missing" in kernel
assert "int x8A4_cli_get_accel_keys(uint32_t chosen_key)" in src
assert "return x8A4_cli_get_accel_keys(requested) == 0 ? 0 : 1;" in cli
assert 'strcmp(model, "iPad13,4")' in cli
assert 'strcmp(osrelease, "23.3.0")' in cli
assert "inspected < 262144" in kernel
assert "x8A4_read_accel_records(kernel_keys, out_keys, count" in src
assert "x8A4_key_table_kread" in src
shared_reader = (root / "Include/x8A4/key_table_reader.h").read_text()
assert "x8A4_accel_offset(count, i, record_size, &byte_offset)" in shared_reader
assert "(uint8_t *)records + byte_offset" in shared_reader
assert "reader(kernel_base + (uint64_t)byte_offset" in shared_reader
assert "record_size != 52" in shared_reader
assert "for (uint32_t i = 0; i < count; ++i)" not in src[src.index("struct x8A4_accel_key *x8A4_get_ioaesaccelkeys"):src.index("/* The legacy cleanup table holds 128 pointers.")]
print("PASS: source regression checks (not live-device validation)")
