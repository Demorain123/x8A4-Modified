# AppleMobileApNonce 路线：21D61 离线复核

日期：2026-11-11  
目标：iPad13,4 / iPadOS 17.3.1 / 21D61  
目的：寻找不读取 IPC 表、原始 kobject 或 0x8A3/0x8A4 记录的替代接口。  
范围：只反汇编工作区已有的 21D61 kernelcache，并阅读公开源码；没有连接设备、打开 IOKit 服务、执行 AES、读写内核、调用 kernel call、修改 Nonce/Generator/NVRAM 或升级系统。

## 结论

精确 21D61 kernelcache 中存在一条与 IOAESAccelerator selector 1 不同的 Apple IOKit 路径：AppleMobileApNonceUserClient selector 0xC8 在内核侧调用 nonce 生成流程。该流程的 _generateNonceHash 确实把 0x8A3 放入内部 AES 描述符，随后把派生的 APNonce 输出到调用者提供的结构缓冲区。它不会导出 0x8A3 的 16 字节 key，也不会导出完整 52 字节记录；没有证据表明它使用 0x8A4。

这条路径在技术上能由目标内核计算 APNonce，但当前不能作为安全、只读的取钥替代方案：

1. externalMethod 对该 userclient 的调用先检查 "root" privilege；这不是普通应用可无条件调用的 selector。
2. 历史实际客户端为打开 AppleMobileApNonceUserClient 使用了 com.apple.security.iokit-user-client-class entitlement；Taurine 还在调用前注入该 entitlement。21D61 对 IOServiceOpen 的确切 entitlement 条件仍未从目标 rootfs 验证。
3. selector 0xC8 的目标调用链含有 nonce 保存处理，失败分支明确记录 “unable save nonce”。因此不能把它当作不触碰 Nonce/Generator/NVRAM 的只读查询；本轮禁止调用它。
4. selector 0xCA 仅可返回 8 字节 generator，而且还受 allow-ap-nonce-retrieval 状态位控制；这不是 APNonce 或 key。

结论分类：APNonce 计算在目标内核实现中已验证；外部调用权限、只读性及当前 Dopamine 进程是否能合法调用均未验证。取得 0x8A3/0x8A4 key value 或 52 字节记录的路线仍然没有。

## 精确 21D61 目标证据

使用已有 kernelcache.decompressed，没有重新下载或解包：

    SHA-256  16e2f6ab693b6d26a038c799e8b17132a5437d4fddd892b90c3d2a6ae8a1843c
    fileset  com.apple.driver.AppleMobileApNonce
    image    fileoff 0x406a60, VM 0xfffffe000740aa60
    __text   fileoff 0x21c13a0, VM 0xfffffe00091c53a0, size 0x2bdc
    cstring  fileoff 0x4070c8, VM 0xfffffe000740b0c8

以下地址均为该静态 cache 的 VM 地址；文件偏移按上述 __text 映射换算。它们不是设备实时读取结果。

### Selector 与权限门

目标 AppleMobileApNonceUserClient::externalMethod 位于 VM 0xfffffe00091c5740 / 文件 0x21c1740。开头把字符串 "root" 传给 clientHasPrivilege；失败时返回 0xe00002c1（kIOReturnNotPrivileged）。这项检查发生在 selector 分派之前。

    91c5764  adrp x1, ...
    91c5768  add  x1, x1, #431       ; 21D61 cstring: "root"
    91c576c  bl   clientHasPrivilege
    91c5770  cbz  w0, reject
    91c5774  mov  w20, #705
    91c5778  movk w20, #0xe000, lsl #16

XNU 公开头文件把 "root" 定义为 kIOClientPrivilegeAdministrator 的名字；这是解释目标字符串的跨版本交叉证据，不替代 21D61 调用本身的直接证据。见 [XNU IOUserClient.h](https://github.com/apple-oss-distributions/xnu/blob/main/iokit/IOKit/IOUserClient.h#L1586-L1590)。

目标 selector 分派：

| Selector | 目标调用 | 输出/作用 | 本轮判断 |
|---:|---|---|---|
| 0xC8 | AppleMobileApNonce::generateNonce，VM 0xfffffe00091c62ec / 文件 0x21c22ec | 生成 nonce 到结构输出缓冲区；后续有保存处理 | 有状态风险，不调用 |
| 0xC9 | clear 路径 | 清除 nonce | 修改操作，禁止调用 |
| 0xCA | AppleMobileApNonce::retrieveNonce，VM 0xfffffe00091c67f4 / 文件 0x21c2894 | 输出当前 64-bit generator | 不是 APNonce/key；受目标 flag 限制 |

0xC8 路径从 91c57d0 读取 IOExternalMethodArguments.structureOutputSize（参数结构偏移 +0x60），从 91c57dc 读取 structureOutput（偏移 +0x58），并把两者传给 generateNonce(void *, size_t *)。该 selector 不从 structureInput 读取数据。XNU 公布的 IOExternalMethodArguments 字段顺序支持这些偏移解释；Apple 的用户态 API 形态见 [IOConnectCallStructMethod](https://developer.apple.com/documentation/iokit/1514274-ioconnectcallstructmethod)。

    91c57b8  cmp  w21, #202           ; 0xCA
    91c57c0  cmp  w21, #201           ; 0xC9
    91c57c8  cmp  w21, #200           ; 0xC8
    91c57d0  ldr  w8, [x19, #96]      ; structureOutputSize
    91c57d8  ldr  x0, [x20, #216]     ; AppleMobileApNonce service object
    91c57dc  ldr  x1, [x19, #88]      ; structureOutput
    91c57e0  add  x2, sp, #40         ; size pointer
    91c57e4  bl   91c62ec             ; generateNonce

generateNonce 要求调用者提供的输出容量至少达到对象字段 this+196，清零输出缓冲区，再调用 _generateNonce。成功返回长度也是 this+196。因此 ABI 的输入为零字节，输出长度由服务初始化时的配置决定；不能仅凭另一系统上的 48-byte 调用推定 21D61 的运行时长度。目标字符串包括 crypto-hash-method、sha2-384、sha1、sha2-384 arm ap、sha1 arm ap，但这些静态字符串不证明本设备运行时选中了哪种 hash 或长度。

### 内部派生与输出

_generateNonce 位于 VM 0xfffffe00091c63a4，从目标 com.apple.System.boot-nonce 路径读取 generator，并把它交给 _generateNonceHash（VM 0xfffffe00091c6c90）。后者检查 this+201 的 entangle-nonce 状态；该状态由服务启动时读取的同名属性设置。该静态逻辑只证明代码路径存在，entangle-nonce 与 hash 方法的实际 21D61 运行值未被离线 cache 验证。

_generateNonceHash 中的关键配置位于 VM 0xfffffe00091c7064..91c70c4 / 文件 0x21c3064..0x21c30c4：

    91c7064  mov  w8, #128            ; key descriptor bits
    91c7068  mov  w9, #2211           ; 2211 = 0x8A3
    91c706c  str  w8, [sp, #64]
    91c7070  str  w9, [sp, #100]      ; descriptor handle
    91c709c  sub  x4, x29, #88        ; zero-initialized IV storage
    91c70a0  add  x6, sp, #64         ; key descriptor
    91c70b0  mov  w3, #16             ; 16-byte input
    91c70b4  mov  w5, #0              ; internal AES operation value
    91c70c4  blraa ...                 ; authenticated provider call

调用通过 AppleMobileApNonce 持有的 provider，使用 vtable slot +0x550；不是普通进程调用被拒绝的 IOAESAcceleratorUserClient selector 1。目标代码之后把 AES 结果交给所配置的 hash 路径并输出 nonce。故此路线实质区别是：受信任的 Apple 内核服务自己使用内部 handle 0x8A3，只把派生结果返回给有权限的调用者，不让用户态取得 key 或自行解引用 kobject。

### 对象安全与权限风险

此路径走 IOKit userclient 的结构式 copyout；调用者不需要自行解析 ipc_entry、ipc_port 或 kobject，也不需要在用户态解码 PAC 指针或维护 SMR 读侧临界区。因此它避开了原有手工 IPC 表遍历的对象生命周期/PAC/SMR 风险。这个判断只针对“调用者不用手工持有原始内核对象”，不证明 Apple 服务内部无竞态或无内核缺陷；目标函数本身仍有认证的间接 provider 调用。该 userclient/selector 是私有 IOKit 接口，不是公开给普通第三方应用的稳定 API。当前目标的 root privilege gate 是确定证据；是否还必须有 AppleMobileApNonceUserClient 类 entitlement、以及 stock 进程是否已有该 entitlement，仍未从 21D61 rootfs 证实。

### 保存副作用与 generator 查询

_generateNonce 在 hash 成功后会进入 nonce save 处理；该调用返回失败时，调用者走到目标 cstring “unable save nonce” 的错误分支（文件偏移 0x407662）。同一目标 image 还包含 _saveNonce、_saveNonceInNVRAM、_clearNonceFromNVRAM 和 _readNonceFromNVRAM 的方法名与代码。静态代码足以说明 0xC8 不应被当作已证明无副作用的查询；其具体保存对象/当前 generator 是否会变化，不在本轮调用验证。

0xCA 的 retrieveNonce 则要求输出长度恰好 8 字节，检查 this+202 后调用 _retrieveNonce 并复制 64-bit 值。该 flag 在启动时由 allow-ap-nonce-retrieval 属性设置。返回对象是 generator，不是 APNonce、派生 key、或完整记录。0xC9 是 clear 路径，明确排除。

## 现成实现与实际适配范围

| 项目/接口 | 源码所示权限与行为 | 可返回数据 | 对 21D61 的证据与限制 |
|---|---|---|---|
| Apple AppleMobileApNonceUserClient selector 0xC8 | 目标调用先检查 root；调用者还可能受 IOKit class entitlement 约束 | 配置长度的 APNonce 输出；不导出 key | 服务、selector、0x8A3 内部 AES 与保存处理均有精确 21D61 cache 证据；外部进程获准调用、运行时 flags 和输出值未验证 |
| Apple selector 0xCA | 同一 root 检查；目标 allow-ap-nonce-retrieval flag 必须允许 | 8-byte generator | 目标 selector ABI 精确；输出不是 APNonce/key，不能完成取钥目标 |
| [TrollNonce](https://github.com/opa334/TrollNonce) | README 标注 iOS 15.0–15.5b4，需 TrollStore 1.0.9+。其 [nonce-uc.m](https://github.com/opa334/TrollNonce/blob/main/noncehelper/nonce-uc.m) 的 UCGetNonce() 调 selector 0xCA，输出 uint64_t；其 [entitlements.plist](https://github.com/opa334/TrollNonce/blob/main/noncehelper/entitlements.plist) 含 platform application 和 AppleMobileApNonceUserClient 类 entitlement | generator；其 set 路径另用 kernel exploits | 成熟历史实现证明旧系统有客户端；不支持 21D61 的证据，不是 0x8A3 key/APNonce 导出接口。README: [支持范围](https://github.com/opa334/TrollNonce/blob/main/README.md) |
| [Taurine](https://github.com/Odyssey-Team/Taurine/blob/b4824a0893717fb221f1215db8e805816a2e1214/Taurine/post-exploit/utils/nvram.swift) | 调用 C8 前做 extractCTBypass() 并注入 com.apple.security.exception.iokit-user-client-class；后续代码通过 kernel read/write 改 nonce 状态 | C8 的 APNonce 输出缓冲区；项目主要用于写 generator/NVRAM | 证明历史越狱客户端需要额外 entitlement 操作；iOS 14 时代实现，不能外推到 21D61，也不符合本轮安全边界 |
| [原版 x8A4](https://github.com/Cryptiiiic/x8A4/blob/99a79f70bc7c90b7bbfcd87b469481581ca43162/Kernel/kernel.c) | io_generate_apnonce() 打开服务、以 CC_SHA384_DIGEST_LENGTH 缓冲区调用 C8，然后丢弃缓冲区；同一源文件还定义清除路径 | 生成服务的返回缓冲区；注释声称生成 APNonce 与 generator | 说明工具作者使用过 C8，但不能证明对 21D61 成功、调用无副作用或能取 key；当前分支的生产路径仍保持 Fail-Closed |
| [Dopamine / libjailbreak](https://github.com/opa334/Dopamine/blob/3.x/BaseBin/libjailbreak/src/jbclient_xpc.h) | 当前公开 XPC header 没有 AppleMobileApNonce/Nonce action；[root domain](https://github.com/opa334/Dopamine/blob/3.x/BaseBin/launchdhook/src/jbserver/jbdomain_root.c) 提供 physrw handoff、thread signing、sysinfo、ucred/MAC label 和 trustcache 等接口 | 没有发现 nonce/key 结果出口 | 不是受保护对象的 nonce broker；其 raw physrw/kernel primitives 不构成本轮允许的安全替代方案。Dopamine 适用范围不能替代目标服务权限证据 |

以上旧项目源码是“存在过这种调用写法”的证据，不是 21D61 上获得授权或运行成功的证据。尤其 TrollNonce 的 get-nonce 只读取 generator；其 set-nonce 会调用利用链，不能当作只读实现。

## 可行性分级与停止条件

### A. 已验证可行

- 21D61 内核服务内部存在不经过用户态 IPC 表遍历的 0x8A3 AES 派生链。
- selector 0xC8 将生成结果放入用户输出结构；因此从功能上说，它是一个 APNonce 输出接口，而不是 key export 接口。
- selector 0xCA 在目标条件允许时返回当前 64-bit generator；它不能替代 APNonce 或 0x8A3/0x8A4 记录。

### B. 有条件可行

若只需要保存 APNonce，仍需同时证明：

1. 21D61 上存在已获授权的 caller（或 Apple stock daemon 的现成只读代理），拥有 root privilege 与目标所需 IOKit class entitlement；不做 entitlement 注入。
2. 存在不改变 Generator/NVRAM 的 APNonce 读取方法。当前发现的 C8 路径含 save 处理，故除非对目标代码证明它只写临时内存/缓存且不会持久化，否则不能调用。
3. 实际 21D61 hash/entangle 配置与输出长度能够从现有、已归档系统文件确认；仅凭内核字符串不足以确认。

可离线验证这些条件的材料是已经保存的 21D61 rootfs 中 userclient/sandbox entitlement、launchd plist、系统 daemon 二进制及其 XPC 路由。本工作区未发现 rootfs/系统 daemon/sandbox profile 文件；本轮不重新下载或解包固件。Dopamine 3.x 公开 XPC 源码没有 nonce action。若以后没有现存系统文件或公开源码提供这些证据，而只能靠设备调用试错，则该分支应保持停止。

### C. 当前条件下不可行 / 应暂停

- 没有发现受支持接口能返回 0x8A3 key bytes、0x8A4 key bytes 或 52-byte 运行时记录。
- 没有发现 Dopamine/libjailbreak 的现成安全 broker 能代为调用 AppleMobileApNonce 并返回只读 APNonce。
- C8 即使可获得权限，也不能在本轮约束下尝试：目标调用链带保存处理，旧项目的调用代码也把它描述成生成 APNonce 和 generator。selector 1、无保护 kread、kernel call、PAC bypass、kernel patch 和 entitlement 注入均不作为替代。
- 0x8A4 / Cryptex nonce 不由这条服务计算；相关路线由另一项研究负责，本报告不重复。

阶段性停止条件：继续暂停 x8A3/x8A4 实机对象读取与 C8 调用。只有出现 21D61 上已有、受支持且只读的系统代理证据，或新的离线材料足以证明 C8 不触碰 Generator/NVRAM 并且目标 caller 已天然具备权限时，才值得恢复 APNonce 接口研究。若这些条件缺失，不再增加外围测试。

## 隐私与保全核对

本报告只包含目标版本静态代码地址、公开 selector、公开 entitlement 名称和 kernelcache 文件哈希。没有写入设备 ECID/UDID/序列号、真实 generator/APNonce、Nonce seed、派生 key、APTicket/SHSH、密钥或私有 kernelcache 内容。kernelcache.decompressed 留在工作区，未上传。

## 复核来源

- 精确目标：本地 kernelcache.decompressed，SHA-256 如上；AppleMobileApNonce fileset / __TEXT_EXEC / __cstring 的文件偏移与 VM 地址如上。
- [XNU IOUserClient.h](https://github.com/apple-oss-distributions/xnu/blob/main/iokit/IOKit/IOUserClient.h)："root" privilege 名与 IOExternalMethodArguments 结构字段；仅作为通用 ABI 交叉参考。
- [Apple IOConnectCallStructMethod 文档](https://developer.apple.com/documentation/iokit/1514274-ioconnectcallstructmethod)：用户态结构式 selector 调用签名。
- [TrollNonce selector 调用](https://github.com/opa334/TrollNonce/blob/main/noncehelper/nonce-uc.m)、[entitlements](https://github.com/opa334/TrollNonce/blob/main/noncehelper/entitlements.plist)、[支持范围](https://github.com/opa334/TrollNonce/blob/main/README.md)。
- [Taurine nonce IOKit/entitlement 路径](https://github.com/Odyssey-Team/Taurine/blob/b4824a0893717fb221f1215db8e805816a2e1214/Taurine/post-exploit/utils/nvram.swift)。
- [Dopamine root XPC actions](https://github.com/opa334/Dopamine/blob/3.x/BaseBin/launchdhook/src/jbserver/jbdomain_root.c) 和 [XPC client API](https://github.com/opa334/Dopamine/blob/3.x/BaseBin/libjailbreak/src/jbclient_xpc.h)。
- [原版 x8A4 的 C8 调用](https://github.com/Cryptiiiic/x8A4/blob/99a79f70bc7c90b7bbfcd87b469481581ca43162/Kernel/kernel.c)。

本轮只进行了离线反汇编和源码阅读；没有运行硬件请求、设备测试、mock 或生产代码测试。
