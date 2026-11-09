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
    "x8A4_accel_offset(count, i, sizeof(*out_keys), &offset)",
    "&out_keys[i]",
    "keys[i].key_id == 0x8A3",
    "keys[i].key_id == 0x8A4",
    "entry->key_sz != 128",
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

assert "X8A4_ENABLE_LIVE_KEY_READ" in cli
assert "live kernel key reading disabled" in cli
print("PASS: source regression checks (not live-device validation)")
