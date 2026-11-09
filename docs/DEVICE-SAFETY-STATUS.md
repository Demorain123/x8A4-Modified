# Safety status: x8A4-Modified, first-stage key-bound repairs

**Status: EXPERIMENTAL / NOT APPROVED FOR DEVICE INSTALLATION OR LIVE KEY READS**

Target research device: M1 iPad Pro (iPad13,4), iPadOS 17.3.1, Dopamine rootless. **Do not publish device ECID, tickets, AES keys, seed arrays, or other device secrets in GitHub issues, CI logs, or PRs.**

## Provenance

This repository was forked from `Cryptiiiic/x8A4` at upstream commit `99a79f70bc7c90b7bbfcd87b469481581ca43162` (v1.0.2). It is **not** automatically based on `PickAstley11/x8A4`. Selected prior research from that fork may be reviewed separately, but has not been silently merged.

## Safeguards implemented in this draft

- Restrict `x8A4_CLI` to `--help` and `--get-accel-key 0x8A3|0x8A4`; remove commands to modify NVRAM.
- Default build **refuses** live kernel key reads (exit code 78).
- Correct erroneous typed-pointer multiplication (52-byte record falsely advanced by 52 * 52).
- Require 1..128 records, checked kernel byte offsets, successful allocation and complete reads; abort if read fails.
- Fail on missing keys or invalid key metadata in APNonce/Cryptex code; repair broken KEY/IV format strings.
- Portable C fixture under ASan/UBSan and static-source checks in CI.
- Attempt an iOS ARM64 macOS CI build for actual Mach-O artifacts.

## Explicit limitations

- These tests do **not** validate the current M1 iPad kernel's structure layout, `IOAESAccelerator` offsets, XPF discovery, Dopamine `libkrw` behavior, memory ownership outside the key-table path, or the correctness of actual extracted key bytes.
- The **underlying library still contains upstream mutation APIs**, even though this restricted CLI does not invoke them. Do not install this experimental library over the already installed one.
- This is not a guarantee of a stable, read-only kernel stack. GitHub Actions build success is not real-device compatibility.
- `0x8A3` and `0x8A4` are supporting archival research material. Collecting them does not guarantee any unsigned iPadOS downgrade.
- No on-device actions, NVRAM edits, NOR rereads, or updates to existing iPadOS archives are part of this PR.

## Required next gate before any live testing

1. CI green (portable sanitizers **and** iOS ARM64 build).
2. Full review of upstream/library mutation symbols, unsafe cleanup patterns, and other paths potentially reachable through initialization.
3. Static audit of built Mach-O code and correct data structure offsets.
4. Controlled verification for M1 iPadOS 17.3.1 without replacing system packages, with clear abort/rollback criteria.
5. If actual 0x8A3/0x8A4 values are safely obtained, validate locally with a separately maintained AES/SHA-384 implementation and preserve in encrypted offline archives. Never post secret values publicly.

**This draft intentionally remains unmerged.**

## Stage 2 — source and build hardening (pending full M1 runtime audit)

- Removed NVRAM write, boot-nonce set/clear, and AppleMobileApNonce mutation entry points from the library and declarations, not just the CLI.
- Repaired an 8-byte kernel read into a 4-byte OS dictionary size; bounded dictionary entry scans and key-name lengths.
- Bounded NVRAM buffer allocations and added allocation checks.
- Failed closed on absent XPF offsets, missing kernelcache path, or unsupported boot-manifest-hash length.
- Added a bounded kernel process-list walk to prevent infinite loops on bad pointers.
- Restricted the opt-in live CLI to root, iPad13,4 and Darwin 23.3.0; it is not enabled in standard builds.
- Key-reader CLI now returns failure when the requested key is missing or invalid, rather than treating missing output as success.
- macOS CI examines the whole dynamic library's write-capable imports; this is a dependency-symbol check, not proof that the jailbreak kernel-read provider cannot modify state.

**Still not ready for on-device installation:** XPF structure and IOAESAccelerator offsets must be verified for the exact M1 17.3.1 kernel, library allocation tracking audited, and emitted keys independently cross-checked. Never replace system-installed packages with this experiment.
