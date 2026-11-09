# x8A4-Modified — M1 / iPadOS 17.3.1 research gate

**Status: experimental. NOT approved for installation, M1 live key reads, or merging.**
Do **not** publish real device AES keys, IVs, ECID, nonce seeds, or SHSH tickets in public GitHub logs.

## Exact objective

Safely retrieve **only** the M1 iPad Pro (iPad13,4) accelerator key records
`0x8A3` (APNonce) and `0x8A4` (Cryptex), including key bytes, IV,
key ID/metadata, and independently verify against already archived iPadOS
17.3.1 signatures. Do not modify the jailbreak setup or overwrite existing
on-device `x8A4` / `libx8A4.1.dylib`. No NVRAM or kernel writes.

This repo was forked from upstream Cryptiiiic/x8A4 at
`99a79f70bc7c90b7bbfcd87b469481581ca43162` (v1.0.2), not automatically
from PickAstley11's fork.

## Implemented and built offline

- Fixed the 52-byte typed-pointer stride error in existing table reads and
  APNonce/Cryptex lookups, plus malformed KEY / IV format strings.
- Removed upstream kernel/NVRAM mutation APIs from sources and headers.
  Restricted CLI accepts only `--help` and one `--get-accel-key`
  (`0x8A3` or `0x8A4`); no setters/clearers are available.
- **CLI now uses a separate bounded scanner** that calls the kernel-reader
  for one 52-byte record per iteration and stops as soon as the chosen key is
  found; it does not allocate or dump the full key table. The separate older
  library function that returns the entire key table is still present for
  other library API users, but it is not called from the restricted CLI.
- Hard key count cap (1 to 128), checks for complete 52-byte read spans
  and kernel pointer/count field spans, read failures, key metadata validation
  and error exit for missing keys. These do NOT prove M1 address correctness.
- M1-specific fail-closed runtime guard in the **opt-in** binary:
  exact `hw.machine=iPad13,4`, `kern.osrelease=23.3.0`,
  `kern.osversion=21D61` and root privileges. This prevents accidental
  cross-build invocation but is NOT a kernelcache offset proof.
- Default binary: `X8A4_ENABLE_LIVE_KEY_READ=OFF`, returns exit **78** for a
  key request **without calling `x8A4_init` or libkrw**.
- The research library output is named `libx8A4Research.1.dylib` to prevent
  a same-name conflict with the currently installed `libx8A4.1.dylib`.
  The command-line binary is `x8A4_CLI`, not the installed `x8A4`.
  No installable Debian package is published.
- CI builds C fixtures with ASan/UBSan, checks dangerous API remnants,
  compiles actual iOS ARM64 Mach-O binaries, checks CLI linkage, and compiles
  an opt-in build for syntax coverage. Only the **disabled** binaries are
  archived for offline binary inspection.

## Remaining acceptance gates BEFORE any live test

1. Latest GitHub CI must be green **including isolated dylib linkage**.
2. Inspect actual built Mach-O instructions, NVRAM/kernel-write imports,
   entitlements, and the source-to-binary key scanning path.
3. Establish the actual **target kernel's** XPF, IPC, IOSurface/libkrw and
   IOAESAccelerator offsets. Source checks and mock-kread are **not** proof
   that the M1 hardware values are correct.
4. Test only with a clearly separated binary/library pair, never replace
   the installed version. First verify help/guard behavior; only then decide
   whether a controlled, single-key read is justified.
5. Check 0x8A3/0x8A4 outputs against an independent AES/SHA-384
   implementation and the already archived original APTicket/Cryptex
   nonce. Store values in a **private encrypted backup**, never CI output
   or a public repository.

**Stop condition:** if any offset, key table count, read result, device
identity, signing/layout assumption or validation step is unexplained,
stop without attempting more kernel reads.

Even verified key material does not guarantee an unsigned 17.3.1 downgrade;
the existing OTA APTicket still has SEP, Cryptex and restore constraints.
