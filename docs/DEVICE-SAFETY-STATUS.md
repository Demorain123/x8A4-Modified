# x8A4-Modified — iPad13,4 / 21D61 research gate

**Status: experimental. NOT approved for live key reads, installation, merge, or publication.**
Keep 0x8A3/0x8A4 record bytes, KEY/IV, nonce seeds, ECID, and tickets out of GitHub, Actions logs, and public attachments.

## Objective and scope

Produce a one-shot research CLI for iPad13,4 / iPadOS 17.3.1 / build 21D61. It initializes once, requests only IDs 0x8A3 and 0x8A4, and stores each exact 52-byte record plus index/metadata in a newly created private directory. Nonce calculations and ticket binding checks remain offline on Linux. The installed x8A4 and jailbreak are not changed.

## Evidence already available

- IPSW and OTA kernelcache entries extracted from the existing archives match: 18,725,015 bytes, SHA-256 22420ad78e3afd2ecd6aa8ef01c017dbb757e01b4d89449c02449bcd02bb72dd.
- Decompressed kernelcache SHA-256: 16e2f6ab693b6d26a038c799e8b17132a5437d4fddd892b90c3d2a6ae8a1843c. Its outer fileset UUID is `a2425a0c161ab96c41866861ba84aacf`; the embedded `com.apple.kernel` UUID is `daf0df6116a43017b9fa195eb20f79b6`. The kernel child is ARM64e, RELEASE_ARM64_T8103, Darwin 23.3.0 / XNU 10002.82.4~3. Offline parsing of the saved file found no kernel nlist symbols; direct named structure-field confirmation is therefore not claimed.
- XPF-only A/B/C completed and archived for this exact kernelcache. The real XPF results are `kernelConstant.T1SZ_BOOT=0x11`, `kernelStruct.task.itk_space=0x300`, `kernelStruct.proc.struct_size=0x730`, and `kernelSymbol.allproc=0xfffffe000aa5b070`. `allproc` is the global pointer slot's unslid kernel virtual address, not a `proc` object pointer; runtime traversal still needs the slide and a slot dereference. The outer fileset UUID and embedded `com.apple.kernel` UUID are distinct Mach-O layer identifiers.
- Target IOAESAccelerator analysis previously verified specialKeys=0xD0, count=0xD8, 52-byte stride, and record fields at offsets 0, 4, 8, 12, 28, 44, and 48. The final pad semantics remain unknown.
- Dopamine 3.0.13 source commit `5b1d2c1c3bf54dd8e3641d29c60cd3a0c13cde88` is useful cross-source evidence for `ipc_port.kobject=0x48` and `IOMachPort.object=0x30` on the iOS 17 family. This is not direct field-offset proof from 21D61. Its `ipc_entry_lookup` helper reads the table pointer with an SMR-pointer primitive but does not establish a lock/SMR read-side critical section for an external reader, so it is not a lifecycle-safety substitute.
- The closest public XNU source tag reviewed is [xnu-10002.81.5 `ipc_entry.c`](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/osfmk/ipc/ipc_entry.c), while the target reports XNU 10002.82.4~3. That source rejects index zero, checks entry bounds through `ipc_entry_table_get`, compares `IE_BITS_GEN` with `MACH_PORT_GEN`, and rejects `MACH_PORT_TYPE_NONE`. Its [entry header](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/osfmk/ipc/ipc_entry.h) defines an `ie_object` pointer at offset 0, `ie_bits` at +8, a 0x18-byte entry, a 5-bit type mask, and an 8-bit generation mask. These values are used only by the portable reference-layout tests; they are not asserted as exact 21D61 layout evidence.
- In that XNU source, `ipc_space.is_table` is an `SMR_POINTER` to a `KALLOC_ARRAY`; [kalloc.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/osfmk/kern/kalloc.c) decodes allocation size from the encoded pointer, and `ipc_entry_lookup` requires the space to stay read- or write-locked and active. `is_table_hashed` and `is_table_free` are counters, not capacity. On arm64e the encoded pointer includes a PAC/signature representation; simply treating a normalized pointer or either counter as an entry count is unsupported. The exact target decode and safe read-side lifetime mechanism remain unresolved.
- The provided device report lists libkrw0 1.1.1-2, libkrw0-dopamine 2.0.4, and hashes for the installed libkrw provider, libkrw core, libjailbreak, and original x8A4. The report's three sysctl values are UNAVAILABLE; it does not prove which provider was loaded into a process or its active runtime configuration.
- PR #1 remains Draft. The starting HEAD for this revision was `54d5707e5d8a14899b1a1bc8a9a6ea32a778b273`; previous CI is not device verification, and this revision still requires its own CI result.

## Changes in this research revision

- Keep the four XPF-resolved values as target evidence. `allproc` denotes a global pointer slot; runtime resolution still requires slide adjustment and dereferencing that slot.
- Keep 0xD0, 0xD8, and the bounded 52-byte scanner; normalize the key-table pointer read from the accelerator object.
- Add a standalone IPC entry validator for invalid names, index zero, unsupported layouts, unknown/insufficient table capacity, arithmetic overflow, generation mismatch, empty capability type, and required-type mismatch. Its accepted layout is explicitly labeled as an XNU 10002.81.5 reference fixture, not 21D61 proof.
- Make `get_ipc_port`, `get_ipc_kobject`, and `get_ipc_kobject_from_iomachport` fail closed before IPC table or object reads. The implementation has no target-verified KALLOC_ARRAY capacity decoder and cannot hold XNU's required ipc_space lock/SMR lifetime protection. Entry bounds and generation/type checks alone do not solve PAC authentication or concurrent object lifetime.
- Label the cached `0x48` and `0x30` IPC offsets as Dopamine cross-source candidates in `offsets.c`; the accessors do not consume them while the target layout remains unverified.
- The old whole-table API is disabled unless a separate legacy macro is explicitly added; the new CLI has no old nonce or whole-table commands.
- One CLI invocation initializes once and scans each ID once. It creates a new mode-0700 directory, saves exact .raw files with mode 0600, and writes JSON/status sidecars without key material. It never prints KEY/IV. Failed reads are not retried; a raw record already saved remains when the other ID fails.
- Record buffers use a volatile wipe after use. The writer rejects existing directories/files and symlink outputs and removes a partial raw file after short-write errors.
- Default builds continue to return exit 78 before x8A4 initialization. The opt-in pair is built and audited in CI but never uploaded. No device extraction is included in CI.

## Acceptance checklist

| Item | Status |
|---|---|
| IPSW/OTA kernelcache identity and ARM64e/T8103/Darwin identity | Passed offline |
| IOAESAccelerator 0xD0 / 0xD8 / 52-byte record evidence | Passed from target-kernel analysis; pad meaning unknown |
| XPF-only A/B/C and four 21D61 values | Completed and archived; no rerun needed |
| IPC invalid-name, bounds, overflow, generation, and type validator | Implemented and sanitizer-tested against an explicitly labeled XNU reference fixture |
| Production IPC table and kobject reads | Disabled before any IPC memory read; fail closed |
| 21D61 KALLOC_ARRAY capacity decode and exact `ipc_entry` layout | Blocked; nearby XNU source explains encoding, but exact target encoding/authentication and size-to-count path are not proven from this stripped kernelcache |
| `ipc_port.kobject=0x48` and `IOMachPort.object=0x30` on exact 21D61 | Cross-source support only; direct target-binary field evidence remains pending |
| SMR lifetime and PAC authentication for external IPC-table reads | Blocked; bounds/generation/type checks do not provide a read-side lock, SMR protection, pointer authentication, or stable object lifetime |
| Four XPF values and kernelcache identity | Passed and retained above |
| Actual libkrw provider loaded by the research process and its runtime ABI | Blocked; package/hash report alone is insufficient |
| Final opt-in Mach-O dependency/import/secret-string audit | Blocked pending CI |
| Live read of 0x8A3 and 0x8A4 | Prohibited until all above blockers clear |
| Offline AES/nonce computation, APTicket/Cryptex binding | Pending actual records; do not modify device Generator/Seed/NVRAM |

## Stop condition

Do not run the opt-in command while the target IPC path, SMR/PAC lifetime handling, actual provider load, or binary audit is uncertain. If an IPC read, pointer normalization, record boundary, or output validation fails, stop with the status files; do not retry. Obtaining a saved SHSH/APTicket does not guarantee a future downgrade.
