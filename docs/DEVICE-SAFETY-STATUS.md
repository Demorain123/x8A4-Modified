# x8A4-Modified — iPad13,4 / 21D61 research gate

**Status: key-acquisition research phase closed; device-specific 0x8A3/0x8A4 key values and full records remain NOT acquired. Production reads remain fail-closed. No live extraction, installation, merge, or publication is approved.**
Keep 0x8A3/0x8A4 record bytes, KEY/IV, nonce seeds, ECID, and tickets out of GitHub, Actions logs, and public attachments.

## Objective and scope

The original objective was a one-shot research CLI for iPad13,4 / iPadOS 17.3.1 / build 21D61. The safety work remains useful, but the project has not reached a safe, authorized route to obtain the device-specific records. This document now records the research closeout and preservation state; it does not authorize execution of the opt-in reader.

No device IOKit request, hardware AES request, live kernel read/write, kcall, entitlement injection, nonce/generator change, installation, restore, or upgrade is part of this phase. Keep production IPC/kobject accessors fail-closed. Existing archive and research artifacts remain unchanged.

## Evidence already available

- IPSW and OTA kernelcache entries extracted from the existing archives match: 18,725,015 bytes, SHA-256 22420ad78e3afd2ecd6aa8ef01c017dbb757e01b4d89449c02449bcd02bb72dd.
- Decompressed kernelcache SHA-256: 16e2f6ab693b6d26a038c799e8b17132a5437d4fddd892b90c3d2a6ae8a1843c. Its outer fileset UUID is `a2425a0c161ab96c41866861ba84aacf`; the embedded `com.apple.kernel` UUID is `daf0df6116a43017b9fa195eb20f79b6`. The kernel child is ARM64e, RELEASE_ARM64_T8103, Darwin 23.3.0 / XNU 10002.82.4~3. Offline parsing of the saved file found no kernel nlist symbols; direct named structure-field confirmation is therefore not claimed.
- XPF-only A/B/C completed and archived for this exact kernelcache. The real XPF results are `kernelConstant.T1SZ_BOOT=0x11`, `kernelStruct.task.itk_space=0x300`, `kernelStruct.proc.struct_size=0x730`, and `kernelSymbol.allproc=0xfffffe000aa5b070`. `allproc` is the global pointer slot's unslid kernel virtual address, not a `proc` object pointer; runtime traversal still needs the slide and a slot dereference. The outer fileset UUID and embedded `com.apple.kernel` UUID are distinct Mach-O layer identifiers.
- Target IOAESAccelerator analysis previously verified specialKeys=0xD0, count=0xD8, 52-byte stride, and record fields at offsets 0, 4, 8, 12, 28, 44, and 48. The final pad semantics remain unknown.
- Exact 21D61 IOAES analysis proves ordinary selector 1 rejects UID handle 0x7D0 before the AES execution method. Root identity or userland entitlement changes do not bypass that earlier target branch. No UID-derived key was obtained.
- Exact 21D61 AppleMobileApNonce analysis shows selector 0xC8 can output an APNonce but not a key or 52-byte record; it has a root privilege gate and a nonce-save path. It was not called and is not treated as a side-effect-free query.
- Project archive inventory (user-confirmed; not reread in this phase): a normal-mode lockdown GetValue("ApNonce") success record exists. It proves an APNonce value was obtained at that time; by itself it does not prove the operation was state-neutral.
- A historical NOR/IM4R generator and a separate field/current generator are both saved and differ. Preserve their provenance separately; neither replaces the other.
- A Cryptex Seed record exists. Its relationship to the independent boot nonce remains unverified; the Linux RSD/Cryptex route belongs to the other research session and is not repeated here.
- Dopamine 3.0.13 source commit `5b1d2c1c3bf54dd8e3641d29c60cd3a0c13cde88` is useful cross-source evidence for `ipc_port.kobject=0x48` and `IOMachPort.object=0x30` on the iOS 17 family. This is not direct field-offset proof from 21D61. Its `ipc_entry_lookup` helper reads the table pointer with an SMR-pointer primitive but does not establish a lock/SMR read-side critical section for an external reader, so it is not a lifecycle-safety substitute.
- The closest public XNU source tag reviewed is [xnu-10002.81.5 `ipc_entry.c`](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/osfmk/ipc/ipc_entry.c), while the target reports XNU 10002.82.4~3. That source rejects index zero, checks entry bounds through `ipc_entry_table_get`, compares `IE_BITS_GEN` with `MACH_PORT_GEN`, and rejects `MACH_PORT_TYPE_NONE`. Its [entry header](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/osfmk/ipc/ipc_entry.h) defines an `ie_object` pointer at offset 0, `ie_bits` at +8, a 0x18-byte entry, a 5-bit type mask, and an 8-bit generation mask. These values are used only by the portable reference-layout tests; they are not asserted as exact 21D61 layout evidence.
- In that XNU source, `ipc_space.is_table` is an `SMR_POINTER` to a `KALLOC_ARRAY`; [kalloc.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/osfmk/kern/kalloc.c) decodes allocation size from the encoded pointer, and `ipc_entry_lookup` requires the space to stay read- or write-locked and active. `is_table_hashed` and `is_table_free` are counters, not capacity. On arm64e the encoded pointer includes a PAC/signature representation; simply treating a normalized pointer or either counter as an entry count is unsupported. The exact target decode and safe read-side lifetime mechanism remain unresolved.
- PR #1 remains Open / Draft / unmerged on fix/nonce-key-bounds-v1; current closeout baseline before documentation edits was 5b24188c53fd8508218460f6bf01c2a4082c6b94. Existing CI is code/build evidence, not device key acquisition. Documentation-only closeout does not require another full build.

## Existing implementation (not authorization)

The following code and historical verification notes describe retained implementation work. They do not make a live read safe or authorized; the default CLI remains disabled and production IPC/kobject access remains fail-closed.

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

| Item | Current status |
|---|---|
| Exact 21D61 kernelcache identity, IOAES static configuration, and XPF-only A/B/C | Previously verified and archived; do not rerun for this closeout |
| Internal 0x8A3 / 0x8A4 derivation and 52-byte record layout | Offline target evidence exists; no device-specific key value or full record has been acquired |
| Ordinary IOAESAccelerator selector 1 for UID handle 0x7D0 | Closed for this route: exact target policy rejects before AES |
| AppleMobileApNonce selector 0xC8 | Not a key-export path; emits APNonce and has save processing; not called |
| Normal-mode lockdown GetValue("ApNonce") | A prior success record exists; no device reread; state-neutrality is not established by that record |
| Generator material | Historical NOR/IM4R and field/current records are both preserved with distinct provenance; do not substitute |
| Cryptex Seed | Record exists; independent boot-nonce pairing is unverified and handled in the other session |
| Production IPC/kobject reads | Disabled before reads; remain fail-closed |
| Supported 21D61 service returning missing key/record | None evidenced; only resume on concrete target protocol, permission, output, and side-effect evidence |
| CI/build checks | Previously recorded CI remains historical build/test evidence; no new tests or full build were run for this document closeout |
| PR #1 | Open / Draft / unmerged; keep Draft |

## Route disposition

| Route | What it could return | Status and reopening condition |
|---|---|---|
| Ordinary libkrw/kread plus userland IPC-table traversal | Raw entry/port/kobject fields if the read succeeds | Excluded: no XNU lock/SMR read-side protection or stable object lifetime; PAC handling is not supplied by ordinary reads. Reopen only if a supported protected-object broker is evidenced. |
| IOAESAccelerator selector 1 with UID handle 0x7D0 | AES output only if the request passes policy | Excluded on 21D61: target rejects the UID handle before AES. Do not retry through another wrapper. |
| AppleMobileApNonce selector 0xC8 | APNonce output, not key bytes or the full key record | Not a route to the missing key. Target requires root privilege and contains save handling; do not call. Revisit only if a safe, already-authorized read-only proxy is proven and APNonce itself is still missing. |
| Lockdown GetValue("ApNonce") | APNonce observed at the time of the saved successful response | Already archived; useful as an observed value, not a key or proof of state neutrality. No reread is needed here. |
| Existing Apple/Dopamine daemon or XPC broker | Unknown until a concrete target protocol is found | No 21D61 endpoint returning the missing key/full record has been evidenced. Resume only with existing target source/binary evidence for access policy, ABI, actual output, and acceptable side effects. |
| kcall, kernel patch, PAC bypass, entitlement injection, or unprotected raw reads | Potential access only by changing or bypassing security boundaries | Prohibited and unauthorized; not a candidate for this project phase. |

## Material value

| Material | What it enables | What it does not enable / current state |
|---|---|---|
| Actual 0x8A3/0x8A4 key value plus matching IV | Local computation of the corresponding APNonce or Cryptex nonce when paired with the correct generator/seed and algorithm | Does not by itself establish record provenance or the correct generator/seed pairing. Not acquired. |
| Complete 52-byte runtime record | Best preservation/audit unit: key, IV, ID, generated/length metadata, and remaining record bytes as emitted by the target | Still needs the correct generator/seed, nonce algorithm, and matching restore/signing context. Not acquired. |
| APNonce output | Preserves the APNonce observed at that capture time and can support later offline comparison/validation | Does not reveal 0x8A3, produce alternate APNonces, or prove the retrieval had no side effect. A normal-mode lockdown success record already exists. |
| Generator | Input material for APNonce derivation and useful provenance for matching a captured APNonce | Does not calculate an APNonce without the correct key/IV. The two saved generator records differ and must remain distinct. |
| Cryptex Seed | Input material relevant to Cryptex nonce derivation | Does not provide 0x8A4 or establish which independent boot nonce it belongs to. The saved pairing remains unverified. |
| Static 21D61 configuration constants | Shows the target's internal derivation inputs and record-generation structure | These are not device-specific secret keys and cannot reproduce the device-specific result alone. |

## Remaining acquisition blockers

The original key-acquisition goal is incomplete. The missing device-specific 0x8A3 and 0x8A4 key values (or full records) were not obtained. The exact target binary proves the internal derivation path and rejects the ordinary UID AES request; the AppleMobileApNonce route returns APNonce rather than key material and is not a safe read-only substitute. No supported 21D61 service or Dopamine/libjailbreak broker returning the missing materials is currently evidenced.

Research may resume only when offline evidence identifies an existing 21D61 endpoint that (1) is usable under an already-present, supported permission model, (2) returns the missing key/full record or a specifically useful nonce result, and (3) has acceptable, documented side effects. If the only route requires kcall, PAC bypass, kernel patching, entitlement injection, or unsafe object reads, keep this phase stopped.

## Stop condition

Keep the production path fail-closed and do not run the opt-in reader. This repository summary contains no actual key, APNonce, generator, Cryptex Seed, ticket, ECID, other device-unique value, or private kernelcache image. The current authorized scope has no implementable route to the missing key material. Resume only on the specific offline evidence conditions listed above; do not add peripheral tests or rebuilds as a substitute. PR #1 stays Draft and unmerged. Existing archives, APNonce record, generator records, and Cryptex Seed record remain preserved with their original provenance.
