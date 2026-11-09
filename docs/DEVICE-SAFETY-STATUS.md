# x8A4-Modified — iPad13,4 / 21D61 research gate

**Status: experimental. NOT approved for live key reads, installation, merge, or publication.**
Keep 0x8A3/0x8A4 record bytes, KEY/IV, nonce seeds, ECID, and tickets out of GitHub, Actions logs, and public attachments.

## Objective and scope

Produce a one-shot research CLI for iPad13,4 / iPadOS 17.3.1 / build 21D61. It initializes once, requests only IDs 0x8A3 and 0x8A4, and stores each exact 52-byte record plus index/metadata in a newly created private directory. Nonce calculations and ticket binding checks remain offline on Linux. The installed x8A4 and jailbreak are not changed.

## Evidence already available

- IPSW and OTA kernelcache entries extracted from the existing archives match: 18,725,015 bytes, SHA-256 22420ad78e3afd2ecd6aa8ef01c017dbb757e01b4d89449c02449bcd02bb72dd.
- Decompressed kernelcache SHA-256: 16e2f6ab693b6d26a038c799e8b17132a5437d4fddd892b90c3d2a6ae8a1843c. The Mach-O fileset contains com.apple.kernel, ARM64e, RELEASE_ARM64_T8103, Darwin 23.3.0 / XNU 10002.82.4~3; embedded kernel UUID daf0df6116a43017b9fa195eb20f79b6.
- Target IOAESAccelerator analysis previously verified specialKeys=0xD0, count=0xD8, 52-byte stride, and record fields at offsets 0, 4, 8, 12, 28, 44, and 48. The final pad semantics remain unknown.
- Dopamine 3.0.13 source commit 5b1d2c1c3bf54dd8e3641d29c60cd3a0c13cde88 provides the matching task-to-IPC-entry-to-ipc_port-to-kobject route and normalizes kernel pointers at each pointer read. Its iOS 16+ proc task handling is proc + sizeof(proc); IPC table/entry values are 0x20, object 0, entry size 0x18; ipc_port.kobject=0x48 for the target OS family.
- Dopamine 3.0.13 source commit `5b1d2c1c3bf54dd8e3641d29c60cd3a0c13cde88` sets `ipc_port.kobject=0x48` for iOS 15.4+ and assigns `IOMachPort.object=0x30` in the iOS 17+ layout branch outside its `hasSPTM`-only adjustments. This supports retaining the wrapper read on iPad13,4 / 21D61; it does not replace direct validation against this target kernelcache. Related source: [info.c](https://github.com/opa334/Dopamine/blob/5b1d2c1c3bf54dd8e3641d29c60cd3a0c13cde88/BaseBin/libjailbreak/src/info.c), [kernel.c](https://github.com/opa334/Dopamine/blob/5b1d2c1c3bf54dd8e3641d29c60cd3a0c13cde88/BaseBin/libjailbreak/src/kernel.c), [util.c](https://github.com/opa334/Dopamine/blob/5b1d2c1c3bf54dd8e3641d29c60cd3a0c13cde88/BaseBin/libjailbreak/src/util.c), [primitives.c](https://github.com/opa334/Dopamine/blob/5b1d2c1c3bf54dd8e3641d29c60cd3a0c13cde88/BaseBin/libjailbreak/src/primitives.c).
- The provided device report lists libkrw0 1.1.1-2, libkrw0-dopamine 2.0.4, and hashes for the installed libkrw provider, libkrw core, libjailbreak, and original x8A4. The report's three sysctl values are UNAVAILABLE; it does not prove which provider was loaded into a process or its active runtime configuration.
- PR #1 remains Draft. Baseline HEAD 781d984fd6ecd4d56e521c100163ac6b53bd53ad has passing CI; that CI is not device verification.

## Changes in this research revision

- Normalize each pointer in allproc, task IPC space, IPC table, IPC entry, ipc_port, and optional IOMachPort paths before the next dereference, using the XPF-resolved T1SZ_BOOT.
- Keep 0xD0, 0xD8, and the bounded 52-byte scanner; normalize the key-table pointer read from the accelerator object.
- The old whole-table API is disabled unless a separate legacy macro is explicitly added; the new CLI has no old nonce or whole-table commands.
- One CLI invocation initializes once and scans each ID once. It creates a new mode-0700 directory, saves exact .raw files with mode 0600, and writes JSON/status sidecars without key material. It never prints KEY/IV. Failed reads are not retried; a raw record already saved remains when the other ID fails.
- Record buffers use a volatile wipe after use. The writer rejects existing directories/files and symlink outputs and removes a partial raw file after short-write errors.
- Default builds continue to return exit 78 before x8A4 initialization. The opt-in pair is built and audited in CI but never uploaded. No device extraction is included in CI.

## Acceptance checklist

| Item | Status |
|---|---|
| IPSW/OTA kernelcache identity and ARM64e/T8103/Darwin identity | Passed offline |
| IOAESAccelerator 0xD0 / 0xD8 / 52-byte record evidence | Passed from target-kernel analysis; pad meaning unknown |
| Dopamine 3.0.13 process/IPC source route and offsets (proc/task, IPC table/entry, kobject, IOMachPort) | Cross-checked; source config is not a target runtime trace |
| 21D61 port kobject → IOMachPort wrapper at +0x30 | Supported by Dopamine iOS 17+ layout branch; direct target-binary confirmation pending |
| Per-pointer normalization and 52-byte output implementation | Source change; requires the single CI build and tests |
| Real T1SZ_BOOT, XPF result values, and active kernelcache path on this device | Blocked |
| Actual libkrw provider loaded by the research process and its runtime ABI | Blocked; package/hash report alone is insufficient |
| Final opt-in Mach-O dependency/import/secret-string audit | Blocked pending CI |
| Live read of 0x8A3 and 0x8A4 | Prohibited until all above blockers clear |
| Offline AES/nonce computation, APTicket/Cryptex binding | Pending actual records; do not modify device Generator/Seed/NVRAM |

## Stop condition

Do not run the opt-in command while the target IPC path, XPF values, actual provider load, or binary audit is uncertain. If an IPC read, pointer normalization, record boundary, or output validation fails, stop with the status files; do not retry. Obtaining a saved SHSH/APTicket does not guarantee a future downgrade.
