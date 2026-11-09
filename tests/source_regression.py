"""Source-level regression checks for the bounded target-record CLI.

These checks do not establish M1 runtime or kernel-offset compatibility.
"""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
src = (root / "x8A4.c").read_text()
cli = (root / "x8A4_CLI.c").read_text()
kernel = (root / "Kernel/kernel.c").read_text()
offsets = (root / "Kernel/offsets.c").read_text()
target = (root / "Include/x8A4/target_key.h").read_text()
archive = (root / "Include/x8A4/private_record_archive.h").read_text()
cmake = (root / "CMakeLists.txt").read_text()
live = src.split("\n#if 0", 1)[0]

for forbidden in (
    "keys + (struct_size * i)",
    "out_keys + (struct_size * i)",
    "Key(0x%04X) KEY:",
    "Key(0x%04X) IV:",
):
    assert forbidden not in live, f"Unsafe or secret-printing pattern remains: {forbidden}"

assert "X8A4_ENABLE_LIVE_KEY_READ" in cli
assert "return 78;" in cli
assert "--export-accel-records" in cli
assert "--get-accel-key" not in cli
assert "x8A4_cli_export_target_records(output_dir)" in cli
assert 'strcmp(model, "iPad13,4")' in cli
assert 'strcmp(osrelease, "23.3.0")' in cli
assert 'strcmp(build, "21D61")' in cli
assert "umask(077)" in cli

init_start = src.index("int x8A4_init(void) {")
assert src.index("x8A4_target_runtime_matches()", init_start) < src.index("if (xpf_init())", init_start)
assert "x8A4_scan_target_key(" in src
assert "x8A4_archive_write_record(dirfd, &record, index)" in src
assert "x8A4_secure_clear(&record, sizeof(record))" in src
assert "X8A4_ENABLE_LEGACY_TABLE_READ" in src
assert "legacy whole-table key reads are disabled" in src
assert "x8A4_get_ioaesaccelkeys(" not in src[src.index("int x8A4_cli_export_target_records"):]

assert "X8A4_RAW_RECORD_BYTES 52U" in archive
assert "O_EXCL | O_NOFOLLOW" in archive
assert "fchmod(fd, 0600)" in archive
assert "record_bytes" in archive
assert "KEY:" not in archive and "IV:" not in archive
assert target.count("x8A4_secure_clear(&entry") == 4

# Each pointer read is normalized before its next dereference.
assert "if (!unsign_ptr(&next) || next == proc) break;" in kernel
assert "if (!unsign_ptr(&itk_space))" in kernel
assert "if (!unsign_ptr(&table))" in kernel
assert "if (ret || !unsign_ptr(&port))" in kernel
assert "if (!unsign_ptr(&port_addr))" in kernel
assert "if (ret || !unsign_ptr(&kobject))" in kernel
assert "koffsets_cached->t1sz_boot > 62" in kernel
assert "sz != sizeof(*value)" in kernel
assert "if (!unsign_ptr(value)) return -1;" in kernel

assert "koffsets_cached->ipc_port_kobject_is_iomachport = 1;" in offsets
assert "koffsets_cached->iomachport_object = 0x30;" in offsets

for forbidden in (
    "x8A4_cli_set_cryptex_seed",
    "x8A4_cli_set_apnonce_generator",
    "x8A4_cli_clear_apnonce_generator",
    '"set-cryptex-nonce"',
    '"set-apnonce-generator"',
    '"clear-apnonce-generator"',
    "KEY: 0x",
    "IV: 0x",
):
    assert forbidden not in cli, f"Mutation or secret output remains in CLI: {forbidden}"

assert "target_compile_definitions(x8A4 PRIVATE X8A4_ENABLE_LIVE_KEY_READ=1)" in cmake
assert 'option(X8A4_ENABLE_LIVE_KEY_READ "Enable EXPERIMENTAL on-device kernel key reads" OFF)' in cmake
print("PASS: source regression checks (not live-device validation)")
