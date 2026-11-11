# IOAES UID 派生路线：21D61 离线结论

日期：2026-11-11  
目标：iPad13,4 / iPadOS 17.3.1 / 21D61  
范围：仅分析工作区中已存在的解压 kernelcache；未连接设备、调用 IOKit、执行硬件 AES、提取密钥、进行内核读写/执行、修改 Nonce/Generator 或升级系统。

## 结论摘要

21D61 的 AppleS8000 AES 驱动在内部启动流程中，确实会使用 UID 硬件句柄 `0x7D0`，将两条静态 16 字节配置分别加密，并把结果写入 ID 为 `0x8A3`、`0x8A4` 的运行时记录。注意：`0x8A3/0x8A4` 是派生记录 ID；目标静态配置实际使用的硬件 AES handle 是 `0x7D0`。目标的 `IOAESAcceleratorUserClient` 有 selector 1 AES 接口，但其策略包装函数在调用 AES 执行函数之前，直接以 `kIOReturnNotPrivileged` 拒绝 `0x7D0`。它也拒绝数值落在 `0x898..0x8fb` 的 handle（该范围包含 `0x8A3/0x8A4`，但这不是内部配置的实际 handle）。

因此，**当前目标上的普通 IOKit `IOAESAccelerator` 请求无法计算或返回 `0x8A3` / `0x8A4` 的 key value**。这项拒绝在 entitlement 检查之前；root 或 Dopamine 的用户态进程身份不会绕过该分支。内部启动派生代码不是可供普通用户态调用的 selector，也没有导出 52 字节记录的接口。

这是对 IOAESAccelerator 这条路线的否定，不证明其他未来的受支持服务一定不存在。生产 IPC/kobject 读取仍应保持 Fail-Closed。

## 目标文件与证据等级

本地已有 `kernelcache.decompressed` 原样用于分析，没有重新下载或解包。SHA-256：

```text
16e2f6ab693b6d26a038c799e8b17132a5437d4fddd892b90c3d2a6ae8a1843c
```

目标 fileset 含 `com.apple.driver.AppleS8000AES` 和 `com.apple.iokit.IOCryptoAcceleratorFamily`。两者相关可执行段已去符号，但代码、数据和字符串仍可反汇编/定位。下文地址是该 cache 的文件偏移和 VM 地址，不是运行时设备读取结果。

| 目标 image / segment | 文件偏移 | VM 地址 | 主要用途 |
|---|---:|---:|---|
| AppleS8000AES `__TEXT_EXEC` | `0x23933e0` | `0xfffffe00093973e0` | 硬件 AES backend |
| IOCryptoAcceleratorFamily `__TEXT_EXEC` | `0x2d90130` | `0xfffffe0009d94130` | 配置派生、userclient |
| AppleS8000AES `__DATA` | `0x3b6f480` | `0xfffffe000ab73480` | 静态配置数组 |
| IOCryptoAcceleratorFamily `__DATA_CONST.__const` | `0xe17138` | `0xfffffe0007e1b138` | provider vtable/常量 |

证据标记：下文的地址、分支和静态字节是**精确 21D61 cache 证据**；旧 iphone-dataprotection 和公开 key 文档仅用于识别历史 ABI/命名，不能证明 21D61 权限；对 21D61 未执行的运行时结果明确标为未验证。

## 静态配置、0x7D0 与运行时 key 的对应关系

AppleS8000 驱动启动路径在 `0xfffffe0009398068..0xfffffe0009398070` 将静态配置数组地址存入对象 `this+0x98`。配置数组从文件偏移 `0x3b6f548` / VM `0xfffffe000ab73548` 开始，项长 24 字节：`+0` ID、`+4` 硬件 key handle、`+8` 16 字节输入。

| 记录 ID | 项偏移 | 硬件 handle | 输入偏移 | 21D61 中的静态输入 |
|---|---:|---:|---:|---|
| `0x8A3` | `0x3b6f620` | `0x7D0` | `0x3b6f628` | `568241656551e0cdf56ff84cc11a79ef` |
| `0x8A4` | `0x3b6f638` | `0x7D0` | `0x3b6f640` | `0c31f7df81924d038cb437fa0360f7c9` |

这些 16 字节是固定的派生输入，不是设备专属 key。设备专属结果由目标硬件的 `0x7D0` 密钥参与运算；静态输入本身不能恢复该密钥或结果。

目标配置处理函数位于 VM `0xfffffe0009d95e68` / 文件 `0x2d91e68`。后段循环从配置项取 handle 和 16 字节输入（约 `0x9d96148..0x9d96158`），清零 16 字节 IV，给内部 key 描述符写入 `0x80`，并以长度 16、数值 mode 0、该 handle 调用内部 AES 方法（约 `0x9d96188..0x9d961f8`）。成功时，将 16 字节输出复制到记录 `+0x0c`，写入 ID、128-bit 长度、generated=1 和 `+0x2c=0`（约 `0x9d96200..0x9d9625c`）。`0x80` 与记录中的 128-bit 长度是该接口/记录的字段值；不能据此断言硅片 UID 根密钥本身是 AES-128。历史 key 文档对 `0x8A3` 的 UID 派生描述为 AES-256-CBC，而 arm64e nonce entanglement 使用派生出的 128-bit key；这与目标记录输出 16 字节并不矛盾。

关键目标指令（省略指针认证序列和错误分支）：

```asm
9d96148  ldr  x8, [x20, #0x98]    ; 静态配置数组
9d9614c  madd x8, x23, x24, x8    ; 24-byte stride
9d96150  ldr  w9, [x8, #4]        ; hardware handle 0x7d0
9d96154  str  w9, [sp, #0x4c]    ; 内部 key descriptor handle
9d96158  add  x2, x8, #8          ; 固定 16-byte input
...
9d96188  blraa ...                ; 创建输入 IOMemoryDescriptor
9d9618c  add  x0, sp, #0x58
9d96194  mov  w2, #0x10
9d96198  bl   ...                  ; 清零 16-byte IV
...
9d961cc  add  x4, sp, #0x58       ; IV
9d961d0  add  x6, sp, #0x28       ; key descriptor (bits=128, handle=0x7d0)
9d961e4  mov  w3, #0x10           ; input length
9d961e8  mov  w5, #0              ; mode
9d961f8  blraa ...                ; internal AES method
...
9d9620c  add  x2, x8, #0xc        ; record key bytes destination
9d9623c  blraa ...                ; copy 16-byte AES output into record
9d96258  stp  w8, w26, [x9, #4]   ; ID + key-size field
9d9625c  strb w27, [x9]           ; generated = 1
```

目标代码把记录数组按 `0x34` 字节分配并清零（约 `0x9d94ddc..0x9d94e04`）。据该写入路径可确定字段：`+0` generated 标志、`+4` ID、`+8` 长度、`+0x0c` 16 字节派生输出、`+0x1c` IV（该路径未写，保持零）、`+0x2c` 零值；`+0x30` 的 4 字节尾部含义未识别。此处能证明运行时记录的生成关系，不能证明本设备实际执行过这段代码或观察到过本设备的 16 字节输出。

**`0x7D0` 的含义：**目标 backend 在 `_configureAES` 附近（VM `0xfffffe000939894c`）对 `0x7D0` 和 `0x7D1` 有分别处理；其他选择路径也专门比较 `0x7D0`。`0x7D0` 十进制为 2000。旧公开接口把 `kIOAESAcceleratorUIDMask` 作为 UID 加密 handle；这与目标静态配置明确把 `0x7D0` 作为硬件 handle 相吻合。因此“目标将 `0x7D0` 用作 UID 硬件密钥句柄”有目标代码 + 历史命名的交叉依据；Apple 未发布 21D61 该驱动源码，不能声称从私有符号/注释直接读到 UID 字样。

**AES mode 的证据等级：**21D61 内部调用传入数值 mode `0`，输入 16 字节、IV 全零。目标 kext 保留 `AES-CBC` 字符串；历史 IOAES 客户端把 `kIOAESAcceleratorEncrypt` 用于 UID 加密，支持将 mode 0 解释为 AES-CBC encrypt。数值、IV、长度、输出位置是目标直接证据；C enum 名称是跨版本交叉证据，不是 21D61 源码定义。`bits=128` 是目标记录/请求参数，不能把它等同于实际 UID 硬件密钥宽度。对于单个 16 字节 block 且 IV=0，该 AES 输出对应记录 key bytes。

## Selector 1 的目标 ABI 与权限分支

`IOAESAcceleratorUserClient::externalMethod` 功能性识别地址：VM `0xfffffe0009d96918` / 文件 `0x2d92918`。provider vtable 数据从文件 `0xe17158` 开始；slot `+0x548` 位于 `0xe176a0`，目标为策略包装函数 VM `0xfffffe0009d94fc8` / 文件 `0x2d90fc8`；slot `+0x550` 位于 `0xe176a8`，目标为底层 AES 执行方法 VM `0xfffffe0009d95308` / 文件 `0x2d91308`。原始 cache 中的函数指针带认证编码；报告记录由目标段映射解析出的代码目标，而非把原始指针整数直接当地址。

| Selector | 21D61 的行为 | 结构长度约束 |
|---:|---|---|
| 0 | 返回 accelerator 信息 | 输出长度必须恰好 `0x28` |
| 1 | 走权限包装后执行 AES | 输入和输出都至少 `0x58`；`0x50` 后的扩展长度需与字段匹配 |
| 2 | 测试路径 | 不返回 key |
| 其他 | 不支持/参数错误 | — |

selector 1 的 64-bit 输入结构由目标 dispatcher 的寄存器/偏移使用恢复：

| 偏移 | 字段 | 目标代码证据 |
|---:|---|---|
| `+0x00` | 输入数据指针 | `ldp x1,x2,[input]` |
| `+0x08` | 输出数据指针 | 同上 |
| `+0x10` | 数据长度（按 `u32` 读取） | `ldr w4,[input,#0x10]` |
| `+0x14` | 16 字节 IV，输入/输出 | 传 provider，随后复制回输出 `+0x14` |
| `+0x24` | mode/operation word | `ldr w6,[input,#0x24]` |
| `+0x28` | 32 字节 key/命令描述符起始 | 传入 provider `x7` |
| `+0x48` | key size bits (`u32`) | 描述符字段 |
| `+0x4c` | key handle (`u32`) | 包装函数读取 `x7+0x24` |
| `+0x50` | UIDPlus 扩展长度 (`u32`) | 与结构尾部长度核对 |
| `+0x58` | 可选扩展数据 | 长度必须匹配 |

这是目标 64-bit ABI 的函数级恢复，不应套用旧资料中的 32-bit 72-byte 结构。AES 数据结果由调用者输出指针接收；结构返回 IV 和长度，不返回内部 52-byte key record。

关键拒绝分支（VM `0xfffffe0009d94fc8`）：

```asm
9d94fec  ldr  w8, [x7, #0x24]       ; handle，即 selector 输入 +0x4c
9d94ff0  mov  w19, #0x2c1
9d94ff4  movk w19, #0xe000, lsl #16 ; kIOReturnNotPrivileged
9d94ffc  sub  w9, w8, #0x7d0
9d95000  cmp  w9, #3
9d95004  b.lo reject                ; 拒绝 0x7d0..0x7d2
...
9d95070  sub  w9, w8, #0x898
9d95074  cmp  w9, #0x64
9d95078  b.lo reject                ; 拒绝 0x898..0x8fb
```

`0x8A3`、`0x8A4` 数值均落在 `0x898..0x8fb`。包装函数随后才继续到权限/entitlement 逻辑和底层 AES 方法。目标中出现的 `com.apple.private.IOAESAccelerator.fdr-key-handle` 分支用于另一个 handle 路径；它不能覆盖更早发生的 UID/上述区间拒绝。实际复现内部派生需要 UID handle `0x7D0`，而它在更早的 `0x7d0..0x7d2` 分支已被拒绝。因而提升为 root 或授予该 entitlement 都不能让当前 selector 1 通过这些目标分支。即使 IOKit service 可以打开，也不代表允许此 AES 操作。

## 候选路线判定

| 候选 | 权限/调用上下文 | 可取数据 | 对 21D61 的判断 |
|---|---|---|---|
| 普通 `IOAESAccelerator` selector 1 | 普通 IOKit connection；调用受目标 policy gate | 对获准 handle 返回 AES 结果与 IV | **不适用**：UID `0x7D0` 与含 `0x8A3/0x8A4` 的区间被明确拒绝 |
| AppleS8000 / IOCrypto 内部派生路径 | 内核启动/驱动内部上下文 | 写入内核记录的 16-byte 派生 key 及元数据 | 目标确有其代码；没有普通用户态 selector 可以直接调用/导出该记录 |
| 旧 iphone-dataprotection 用户态客户端 | 旧系统上的 IOKit 调用 | 其旧设备/系统上可请求 UID AES | 仅历史参考；源码遇到 `kIOReturnNotPrivileged` 后转向 kernel patch；不能证明 21D61 可用 |
| Dopamine/libkrw 当前用户态 | 越狱 root 与内核读能力 | 不是受支持的 UID AES 服务，也不自动提供对象引用/生命周期保障 | 不绕过 21D61 userclient 的 caller-independent handle gate；kcall、patch、PAC bypass、原始对象读取都未授权且本轮禁止 |
| 其他 Apple IOKit/daemon 服务 | 必须找到目标版本实际存在的受支持 endpoint，并验证 caller policy | 只有 endpoint 明确返回 key 或等价 nonce 时才有用 | 本轮没有找到具备 21D61 ABI/权限/返回值证据的替代服务；目前是具体阻塞项 |

历史 `iphone-dataprotection` 客户端明确用 `IOConnectCallStructMethod` 调 UID AES，并在 `kIOReturnNotPrivileged` 后尝试 kernel patch。它说明“服务存在”并不意味着 UID 操作获准；它是旧平台证据，不是 21D61 成功证明。Dopamine 的 root/kernel-read provider 也不是此 IOKit 策略的等价替代。PAC 保护内核指针的认证/使用，SMR 读侧临界区保护对象/表的并发生命周期；本 IOKit 路线若获准，本可通过受控参数/拷贝结果避开用户态自行解引用这些对象，但当前权限 gate 先行拒绝。PAC/SMR 本身不会授予调用权限，也不会把被拒绝的 handle 变成可调用。

## 对 APNonce、Cryptex nonce 和归档的意义

- `0x8A3` key 与 IV、generator 一起用于 APNonce entanglement；现有源码对 arm64e 路径加密 `{0, generator}` 后做哈希。
- `0x8A4` key 与 IV、Cryptex seed 一起用于 Cryptex nonce；现有源码加密 16-byte seed 后做哈希。
- 单有 16-byte key 并非总是足够：还需保留/验证 IV（目标生成路径为全零）、正确 generator/seed、字节序、哈希规则及对应票据关系。
- 完整 52-byte 原始记录对审计/保全更好，保存 ID、generated、key-size、key、IV 和保留字段；但计算 nonce 的核心材料是 key+IV 与 generator/seed。当前 selector 既不给 key bytes，也不给这条记录。
- 因此本设备本轮没有新增任何设备专属 key/record。已有签名、归档和其他材料应继续原样保存；这份静态配置研究不能替代 0x8A3/0x8A4 设备记录。

## 可行性结论与解除条件

### A. 已验证可行

- 精确 21D61 cache 中存在 `0x8A3`、`0x8A4` 两个静态配置及内部 UID-backed 生成/落盘记录路径。
- 精确目标 selector、结构 ABI、provider slot、handle gate 和返回结构可由离线反汇编复核。
- 精确目标普通 userclient 会在 AES 执行前拒绝 `0x7D0` 和 `0x8A3/0x8A4` 区间。

### B. 有条件可行

只有在离线材料中找到另一项**确实存在于 21D61 且受支持**的 Apple 服务，并证明其消息 ABI、调用权限和返回值能提供 key 或等价 nonce，才值得恢复普通服务路线。证据必须来自目标 binary/source 或可验证协议；单纯发现 service 名、能打开 connection、或历史版本曾成功，均不够。

### C. 当前条件下不可行

已知 `IOAESAccelerator` selector 不能在当前限制下完成目标。只有绕过/改变 policy（kernel patch、kcall、PAC bypass 等）或读取内部原始记录才可能触及内核路径；这些风险路线本轮未获授权且明确禁止，不能建议实机尝试。继续增加普通 AES mock、ABI 测试或外围 PASS 不会解除该策略拒绝，已进入收益递减阶段。

**恢复研究的触发条件：**出现目标 21D61 的具体替代 endpoint/daemon、可复核的权限依据和返回 key/nonce 的协议证据。缺少任一项，都应保持停止，不连接设备、不执行取钥。

## 复核来源

- 精确 21D61 静态证据：工作区原有 `kernelcache.decompressed`，上述 SHA-256、offset、VM 地址、字节和值；私有 kernelcache 未复制到报告或上传。
- 历史 IOAES 客户端：[iphone-dataprotection `IOAESAccelerator.c`（L628-L674）](https://github.com/nabla-c0d3/iphone-dataprotection/blob/master/ramdisk_tools/IOAESAccelerator.c#L628-L674)，UID 请求与 `kIOReturnNotPrivileged` 后处理；仅作为旧实现参照。
- 历史 `0x7D0`、`0x8A3` 说明：[The Apple Wiki AES Keys](https://theapplewiki.com/wiki/Key_0x837#Key_0x8A3)，其中说明派生 key 是以静态输入和 UID key 生成，并描述旧版 key/nonce 计算；不是 21D61 目标证据。
- APNonce/Cryptex key 依赖：[tsschecker README（APNonce 与 Cryptex1）](https://github.com/1Conan/tsschecker/blob/main/README.md#L223-L239)，说明 APNonce 用 `0x8A3`、Cryptex nonce 用 `0x8A4` 与 seed。
- 项目现有离线 nonce 逻辑：[x8A4.c](../../x8A4.c) 的 `x8A4_get_apnonce()`、`x8A4_get_cryptex_nonce()`；本轮没有执行这些函数。

本轮只整理和保存研究文档；没有改生产路径、执行测试或硬件调用。因为目标反汇编已经给出确定拒绝，额外 Mock 无法验证真实权限，因此没有增加测试。文档包含目标固件静态配置常量和 kernelcache 文件哈希，不含私有 kernelcache、设备唯一标识、实际派生 key、Nonce/seed 值或票据。
