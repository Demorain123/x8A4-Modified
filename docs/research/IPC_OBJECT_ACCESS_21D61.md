# IPC object access audit for 21D61

Date: 2026-11-10  
Scope: offline source and Mach-O review only. No device access, kernel reads,
key extraction, kernel execution, nonce changes, or firmware changes were
performed.

## Decision

There is a safe object-reference path **inside XNU's kernel call paths**, but
the reviewed user-space interfaces do not expose it as a reusable raw-object
API. Dopamine's `ipc_entry_lookup()` and `kread_smrptr()` are address helpers;
they do not acquire the IPC-space lock, hold an SMR read section, retain the
port/object, or authenticate the pointer. A generic libkrw `kread()` does not
provide those object-lifetime guarantees either.

Therefore the current x8A4 process has no verified safe path to the
`IOAESAccelerator` object address needed by its private key-table reader.
Production `get_ipc_port()` and both kobject accessors must stay fail-closed.
Calling XNU helpers through a kernel-call primitive or PAC bypass would be a
separate high-risk design requiring explicit authorization; it was not
attempted.

## Candidate access mechanisms

| Candidate | Applicability to iPadOS 17.3.1 | Safety guarantee | Why it does not currently unblock x8A4 |
|---|---|---|---|
| Public Mach port operations (`mach_port_type`, ref-count queries, normal send/receive) | Available to an ordinary process | The kernel performs its own lookup and rights handling for each operation | Results are capability metadata or IPC behavior; no generic API returns an `ipc_port *` or kobject address |
| Public IOKit service/connection calls | Available for services that publish a user-client interface | Dispatch occurs through the kernel's IOKit/IPC path, where the service controls object use and references | The returned `io_object_t`/`io_connect_t` remains an opaque Mach capability. No reviewed API returns the `IOAESAccelerator` object's kernel address or its private key-table pointer |
| XNU `ipc_entry_lookup()` plus `ipc_kobject_get_locked()` | Kernel-internal only | `ipc_entry_lookup()` requires an active, read/write-locked `ipc_space`; kobject lookup requires the port lock and checks active/type. The kobject field is authenticated in XNU's accessor | These are internal kernel routines, not user-space APIs. The reviewed Dopamine and libkrw interfaces do not invoke them inside a lock/ref-safe kernel path |
| XNU `ipc_kobject_get_stable()` | Kernel-internal, only for types with permanent port/object association | It asserts the type is registered as stable and uses the locked getter | No public user-space entry point exposes it; stability is type-specific and cannot be inferred for this service |
| Dopamine 3.0.13 `ipc_entry_lookup()` / `kread_smrptr()` | Source has iOS 16+ branches, including the Darwin 23 family | None beyond reading and transforming values | The helper reads `ipc_space.table` and computes `table + sizeof(ipc_entry) * (name >> 8)`. It does not check table bounds, generation, capability type, locks, or object references. `kread_smrptr()` handles the pointer representation; it does not establish an SMR read-side critical section |
| libkrw `kread()` | Available through the project's read provider when initialized | A provider may report read errors; this is not a port/object lifetime guarantee | A successful byte read can still race table replacement/object destruction and does not authenticate PAC-signed fields |
| Dopamine `kcall()` | Present as an execution primitive; on arm64e its availability is gated by `usesPACBypass` in the reviewed source | No generic lock, reference, or transaction semantics | This would execute kernel code and depends on privileged/PAC-bypass machinery. It is not a supported object-access wrapper and is outside this task's authorization |

### Source positions and candidate-specific limits

- **Public Mach operations:** XNU's `osfmk/ipc/ipc_entry.c` is the kernel-side
  lookup path used when Mach operations resolve a name. A public call is
  suitable for safely asking the kernel to perform one operation on a right;
  the handle and rights must be valid. The operation does not return a
  reusable `ipc_port *`, and no reviewed API returns the private accelerator
  object address. A service-specific data-returning method would need to be
  found and verified; none was established here.
- **Public IOKit service/user-client operations:** `iokit/Kernel/IOUserClient.cpp`
  contains the kernel-side `IOMachPort` handling. One reviewed conversion
  helper locks the wrapper, reads its object, adds a reference, and then
  returns that reference to another kernel caller. User processes receive
  opaque `io_object_t`/`io_connect_t` capabilities, not that kernel pointer.
  The unverified assumption would be that IOAESAccelerator exposes a public
  method returning these keys; no such method was identified.
- **XNU internal accessors:** `osfmk/ipc/ipc_entry.c` and `ipc_space.h` require
  the active IPC space to be locked while an entry is resolved. The
  `ipc_kobject.c` / `ipc_port.h` path requires a locked, active port and
  authenticates the manually PAC-signed field. These are the relevant safety
  contracts for the target family, but they are kernel-private symbols and
  cannot be called by an ordinary x8A4 process.
- **Dopamine/libjailbreak:** pinned source locations are
  `BaseBin/libjailbreak/src/kernel.c` (`ipc_entry_lookup`), `info.c` (version
  offset selection), and `primitives.c` (kernel-call availability). They
  provide offset/read helpers and an optional execution primitive, not a
  demonstrated lock/ref-safe external object getter. Their use assumes a
  working kernel read primitive; that alone does not prove object lifetime.
- **libkrw:** `Siguza/libkrw/include/libkrw.h` defines raw-address `kread()`
  and explicitly warns that direct kernel reads can panic the kernel. Its
  provider API reports read failures but has no IPC-space lock, SMR guard,
  port reference, or PAC-authentication contract.
- **Other read/write primitives:** the reviewed `felix-pb/kfd` project
  describes a kernel read/write interface; code search found no
  `ipc_entry_lookup` or `kread_smrptr` accessor. That is not proof that no
  downstream fork has one, but no object-lifetime-safe IPC API was identified
  in the reviewed implementation.

Any design that calls XNU internals through `kcall`, defeats PAC, or obtains
additional kernel execution privileges is a separate high-risk route. It is
not authorized here and was not attempted.

XNU's `iokit_copy_object_for_consumed_kobject()` demonstrates a legitimate
in-kernel ownership path: it locks the `IOMachPort`, reads its object, adds an
object reference, unlocks, and returns that referenced `OSObject` to a kernel
caller. This proves the framework has an internal safe pattern; it does not
disclose the raw object address to x8A4 or provide a user-space getter.

## 21D61 binary observations

The already-present local `kernelcache.decompressed` was read without
re-downloading or re-decompressing it. Its SHA-256 is
`16e2f6ab693b6d26a038c799e8b17132a5437d4fddd892b90c3d2a6ae8a1843c` and its
size is 63,635,456 bytes. Mach-O metadata identifies an ARM64e `MH_FILESET`
whose kernel version string is `Darwin 23.3.0 ... xnu-10002.82.4~3 ...
RELEASE_ARM64`.

The root kernel image has an empty `LC_SYMTAB` (`nsyms=0`, string table size
1), but retains `LC_FUNCTION_STARTS`. The image contains the `IOMachPort`
class-name string. These facts identify the target binary and show why a
string-only scan cannot establish field offsets: it does not map a field
access to a named function or prove which source revision produced that code.
No `ipc_entry_lookup`, `ipc_port_translate_send`, or `kalloc_array` symbol was
available in the image to anchor this pass. Their missing symbol names do not
mean the routines are absent.

A second read-only Mach-O pass walked all 272 `LC_FILESET_ENTRY` child images
in the already-decompressed file. Every child Mach-O also had `LC_SYMTAB`
`nsyms=0`. The byte strings include `IOMachPort` (5 occurrences) and
`IOAESAccelerator` (32 occurrences across several embedded images), but these
are class/service-name evidence only. They do not prove a member offset or
that a particular load belongs to the object path under study. The available
GNU `objdump` cannot decode this Mach-O/arm64e fileset, and no compatible
arm64e disassembler is installed in this scratch environment; therefore this
pass does not claim target instruction-level field proof.

Apple's OSS XNU tag `xnu-10002.81.5` was used only as a nearby source reference;
it is not the kernel version reported by 21D61. I could not fetch an Apple OSS
tag for `xnu-10002.82.4` or `xnu-10002.82.4~3` in this pass.

| Item | Nearby source / Dopamine evidence | 21D61 status |
|---|---|---|
| `ipc_space.is_table` and table capacity | XNU defines `is_table` as an SMR pointer to a signed KALLOC_ARRAY. The generated table count is derived from the decoded allocation size; `is_table_hashed` and `is_table_free` are usage counters, not capacity. In the arm64e source path, KALLOC_ARRAY has distinct zone/VM size encodings and `__kalloc_array_decode()` returns base and byte size. | Exact 21D61 decoder, pointer authentication context, and decoded count not established. Do not decode with a guessed mask or substitute either counter |
| `ipc_entry` size/fields | XNU reference layout has `ie_object` at 0, `ie_bits` at 8, a 0x18-byte entry, type mask `0x001f0000`, and generation mask `0xff000000`. `ipc_entry_lookup()` checks index, table bounds through the generated accessor, generation, and non-empty type while the space lock is held | Candidate only; not proven from the stripped 21D61 binary |
| `ipc_port.ip_kobject` | XNU marks the field manually PAC-signed. Its accessor authenticates using the field address and a discriminator incorporating the kobject type and port flags. Dopamine assigns `0x48` in its iOS 15.4+ branch and does not replace it for iOS 17 | `0x48` is cross-source evidence, not a 21D61 field-offset or PAC-authentication proof |
| `IOMachPort.object` | The nearby XNU class declares the object pointer PAC-signed. Dopamine assigns `0x30` in its iOS 17+ branch | Target string confirms the class is present; exact 21D61 offset, PAC context, and reference behavior remain unproven |
| `IOAESAccelerator.specialKeys`, count, and record | Prior target-kernel analysis recorded in `docs/DEVICE-SAFETY-STATUS.md` supports offsets `0xd0` / `0xd8`, 52-byte stride, and record-field offsets 0, 4, 8, 12, 28, 44, and 48; final pad semantics remain unknown | This review did not repeat that analysis. The source code still hardcodes those offsets, and the table-pointer PAC/lifetime guarantees are separate and unresolved |
| SMR and object lifetime | XNU lookup requires `ipc_space` locking. XNU kobject reads require a port lock or a permanent type-specific association; IOKit RPC adds references under its own lock | No user-space provider or helper in the reviewed path supplies equivalent protection |

The nearest arm64e XNU source makes the capacity path concrete: `ipc_entry_table`
is declared as a KALLOC_ARRAY of `struct ipc_entry`; its generated count is
`size_to_count(__kalloc_array_size(array))`, and the entry accessor checks the
index against the decoded allocation size with overflow checking. In that
source, the KALLOC_ARRAY tag position is
`KALLOC_ARRAY_TYPE_SHIFT = 64 - T1SZ_BOOT - 1`; a set tag denotes the zone
encoding and a clear tag denotes the VM encoding. The encoded size class/page
count is decoded differently for those two cases, and the decoded base has
the encoding bits removed.

The previously archived, exact-target XPF result `T1SZ_BOOT=0x11` would imply
a candidate tag position of bit 46 **if** 21D61 uses the same arm64e decoder
as xnu-10002.81.5. This is a conditional derivation from adjacent source, not
an exact 21D61 decoder proof. It must not be turned into a production mask.
The field is also declared as both an SMR pointer and a
`XNU_PTRAUTH_SIGNED_PTR`, so decoding an arbitrary `kread()` snapshot without
the target's authenticated/serialized-load context does not establish a
valid table base or a stable table.

The five-bit reference type mask can only produce values 0 through `0x1f`, and
the reference's known-type mask is `0x1f`. Consequently
`X8A4_IPC_INVALID_TYPE_BITS` is an unreachable defensive branch for this
reference layout. It remains useful only if a future accepted layout widens
the field or narrows its known-bit set. This does not establish the 21D61
layout.

## Distance to 0x8A3 / 0x8A4

The current opt-in code path would:

1. Resolve the ordinary `IOAESAccelerator` service port.
2. Obtain its kernel object through `get_ipc_kobject()`.
3. Read the object's `special_keys` pointer and count (hardcoded as `0xd0`
   and `0xd8` in `Kernel/offsets.c`; prior target-kernel analysis supports
   these field offsets and the 52-byte record layout).
4. Read bounded 52-byte records and select key ID `0x8A3` or `0x8A4`.

Step 2 is not safe today. The prior evidence for `0xd0`/`0xd8` and the record
layout does not supply a stable authenticated object reference, prove the
pointer's PAC context, or prevent the object/table from changing during
`kread()`. Those are independent requirements. No key bytes were read or
exported.

## Feasibility and stop condition

### A. Verified feasible

- Offline IPC argument/address validation and fail-closed behavior are
  maintainable and testable.
- XNU itself has correct kernel-internal lock/type/PAC accessors for IPC and
  kobjects; standard IOKit RPC can retain objects for its own operations.
- Existing XPF A/B/C results remain complete and are not repeated here.

### B. Conditionally feasible

Continue offline only to close the remaining layout gaps if one of these
evidence sources becomes available:

- a source release or symbol map matching `xnu-10002.82.4~3`, or a
  function-level disassembly/symbolication of the existing kernelcache
  sufficient to prove the `ipc_entry`, KALLOC_ARRAY, `ipc_port`, and
  IOMachPort field accesses. This can be done offline and would improve layout
  confidence, but would **not** make raw reads lifetime-safe;
- target-matched proof of the KALLOC_ARRAY capacity encoding and authenticated
  pointer handling, without guessed masks or counters.

To unblock extraction itself, independently establish either (a) a supported
user-visible IOAESAccelerator method that returns the required material
without exposing a raw kernel address, or (b) a kernel-side accessor that
accepts a legitimate user handle and performs the XNU locking, reference, and
PAC work internally. No such interface was found. If (b) requires `kcall`, a
PAC bypass, or additional privilege, it is high-risk and requires separate
explicit authorization; it was not attempted.

Any kernel-call/PAC-bypass route would require a separate authorization and a
design that proves the lock, reference, and PAC contracts. It is not part of
the conditional offline work above.

### C. Current constraints make raw-key extraction infeasible

With only an ordinary x8A4 process plus generic `kread`, there is no reviewed
mechanism to obtain the raw kobject pointer with XNU-equivalent locking,
reference, and PAC authentication. Since kernel execution, PAC bypass, and
live kernel reads are prohibited here, the production extraction route must
remain closed. The 21D61 layout work may continue offline, but it cannot
resolve that execution-context/lifetime blocker by itself. Further generic
IPC tests would not reduce this route-level blocker.

Pause criterion: stop x8A4 work at the fail-closed research stage if the exact
source/symbol mapping and a supported safe object-acquisition interface cannot
be found offline. Resume only when one of the concrete evidence sources above
is available; do not substitute CI success or nearby-version offsets for
those proofs.

## Sources

- [XNU `ipc_entry.c`, lookup and lock requirement](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/osfmk/ipc/ipc_entry.c#L98-L128)
- [XNU `ipc_space.h`, signed SMR table pointer and serialized load](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/osfmk/ipc/ipc_space.h#L123-L175)
- [XNU `ipc_entry.h`, entry fields and generation/type masks](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/osfmk/ipc/ipc_entry.h#L107-L145)
- [XNU `kalloc.h`, generated bounds/count helpers](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/osfmk/kern/kalloc.h#L955-L1074)
- [XNU `kalloc.h`, decoded size/base helpers](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/osfmk/kern/kalloc.h#L1190-L1224)
- [XNU `kalloc.c`, arm64e KALLOC_ARRAY size encoding](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/osfmk/kern/kalloc.c#L2044-L2101)
- [XNU `ipc_kobject.c`, PAC authentication and locked/stable accessors](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/osfmk/kern/ipc_kobject.c#L850-L930)
- [XNU `IOUserClient.cpp`, `IOMachPort` layout](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/iokit/Kernel/IOUserClient.cpp#L130-L215)
- [XNU `IOUserClient.cpp`, locked object retain and reference](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/iokit/Kernel/IOUserClient.cpp#L654-L675)
- [Dopamine 3.0.13 `kernel.c`, `ipc_entry_lookup`](https://github.com/opa334/Dopamine/blob/5b1d2c1c3bf54dd8e3641d29c60cd3a0c13cde88/BaseBin/libjailbreak/src/kernel.c#L89-L102)
- [Dopamine 3.0.13 `info.c`, inherited `0x48` and iOS 17 `0x30` selections](https://github.com/opa334/Dopamine/blob/5b1d2c1c3bf54dd8e3641d29c60cd3a0c13cde88/BaseBin/libjailbreak/src/info.c#L301-L311)
- [Dopamine 3.0.13 `info.c`, iOS 17+ `IOMachPort.object`](https://github.com/opa334/Dopamine/blob/5b1d2c1c3bf54dd8e3641d29c60cd3a0c13cde88/BaseBin/libjailbreak/src/info.c#L406-L446)
- [Dopamine 3.0.13 `primitives.c`, `kread_smrptr`](https://github.com/opa334/Dopamine/blob/5b1d2c1c3bf54dd8e3641d29c60cd3a0c13cde88/BaseBin/libjailbreak/src/primitives.c#L276-L295)
- [Dopamine 3.0.13 `primitives.c`, `kcall` availability gate](https://github.com/opa334/Dopamine/blob/5b1d2c1c3bf54dd8e3641d29c60cd3a0c13cde88/BaseBin/libjailbreak/src/primitives.c#L419-L430)
- [libkrw raw kernel-read API contract](https://github.com/Siguza/libkrw/blob/master/include/libkrw.h#L38-L70)
- [kfd kernel read/write project](https://github.com/felix-pb/kfd)
