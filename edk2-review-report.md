# EDK2 库调用桥审查报告（commit e364674，分支 edk2_codegraph）

- **审查对象**：`src/resolution/frameworks/edk2.ts` 的 `LibraryIndex` / `buildLibraryIndex` / `resolve()` 库调用分支（calls）、RefusedRef 接线、`__tests__/edk2-resolution.test.ts` 与 `__tests__/edk2-index-integration.test.ts` 新增测试。
- **审查 lens**：框架通用性 / 声明驱动纯度 / 与既有适配协同 / 交付完整性（ReportEdk2）；代码正确性 / 边界 / 性能（CheckEdk2，见第五节标注）。
- **证据约定**：`文件:行号` + 语料引用；无直接观察处标 `[INFERENCE]`；语料为 `/root/code/edk2`（tianocore 主分支）。live DB `/root/code/edk2/.codegraph/codegraph.db` 为旧产物，不作为证据。
- **验证动作**：`npx vitest run __tests__/edk2-resolution.test.ts __tests__/edk2-index-integration.test.ts` → 76/76 通过（2 文件）。静态验证了语料中 55 个 `.dsc`、INF/DSC 分区形态、`!include` 片段、架构分区源文件、多 LIBRARY_CLASS 行等。
- **审查轮次**：`git log --oneline -15` 确认 e364674 之前已有 33a05dc（声明集合驱动）、71217f5、6354773、5b6047e 等多轮 EDK2 适配。

---

## 执行摘要

**结论：该桥的声明链设计（INF [LibraryClasses] → DSC [LibraryClasses]/唯一 LIBRARY_CLASS 回退 → 实例 [Sources]）本身是声明驱动的，且对"单平台、单顶层 [LibraryClasses]、无条件行"的迷你项目成立；但对真实 EDK2 树（模块类型限定分区、`!if`/`!else` 条件行、`!include` 片段、多平台 DSC、架构分区源文件——语料中全部存在且是常态）存在一个 P0 级缺陷：所有"已声明类但实例有歧义"的合法库调用会被 RefusedRef 永久删行（数据丢失），与提交自身"解析 115k+ 未解析调用"的目标相悖。另有多项 P1/P2 问题（架构变体重复目标、多 DSC 合并、commit message 验证路径不实、docstring 自相矛盾、RefusedRef 语义不兼容）。**

**总体判定：`incorrect`（存在 P0，需修复后再合并）。**

---

## 一、声明驱动纯度

### 1.1 决策点与声明来源（全部核对）

| 决策点 | 声明来源 | 是否形状猜测/语料特判 |
|---|---|---|
| caller 属于哪个模块、声明哪些类 | 模块 INF `[Sources]` + `[LibraryClasses]` | 否（规格语法） |
| 类 → 实例 | DSC `[LibraryClasses]` 顶层 / `<LibraryClasses>` 块内覆盖 / 唯一 `LIBRARY_CLASS` 回退 | 否，但"唯一实例回退"是一种推断（见 1.2-c） |
| 函数 → 实例归属 | 实例 INF `[Sources]` 的 .c 文件中的 function 节点 | 否 |
| 拒绝（RefusedRef） | caller 未声明提供类 | 语义问题见第三节 3.1 |

无硬编码包名/路径/函数名。正则均为 EDK2 语法（`[Section]`、`Class|Impl.inf`、`LIBRARY_CLASS = X`），非语料形状。**纯度结论：机制声明驱动，但存在三类"声明语义丢失"，均非猜测而是解析不完整（见 1.2）。**

### 1.2 声明语义丢失点（非形状猜测，但偏离"声明集合驱动"的完整性）

- **a. 模块类型限定分区被合并**：`parseInfLight` 与 DSC Pass 2 用 `section.replace(/\.[A-Za-z0-9_]+/g,'')` 把 `[LibraryClasses.common.SEC]`、`[LibraryClasses.common.DXE_DRIVER]` 等全部归并为 `libraryclasses`（`src/resolution/frameworks/edk2.ts:226`、`:298`）。语料常态：`OvmfPkg/OvmfPkgX64.dsc` 中 DebugLib 在 10+ 个模块类型分区各有映射（`:289/:291/:323/:325/:343/:345/:380/:382/:400/:402/:425/:427/:442/:444/:476/:478/:493/:495/:516/:518/:524/:526/:542/:544`）；`MdeModulePkg/MdeModulePkg.dsc` 的 MemoryAllocationLib 映射 6 个不同实例（`:117/:121/:128/:134/:140/:148/:156/:164/:170/:176`）。合并后 `defaultInstances['DebugLib']` 等天然 ≥3 项 → `effectiveInstance` 返回 null（`edk2.ts:429-430`）。
- **b. `!if`/`!else`/`!elseif` 条件行双分支都被采集**：`parseInfLight` 只跳过 `!` 行本身（`edk2.ts:229`），分支两侧的映射行都进 `defaultInstances`（例：OvmfPkgX64.dsc `:288-292` 同时收 `BaseDebugLibSerialPort` 与 `PlatformRomDebugLibIoPort`）。即使类只在一个分区出现，条件分支也会把实例数翻倍 → 歧义。
- **c. "唯一 LIBRARY_CLASS 回退"是推断而非全量声明**：当 DSC 无映射或映射被跳过时，用"全语料中唯一声明 LIBRARY_CLASS=C 的 INF"当实例。这是合理的最小推断，但注意它与 DSC 权威性语义存在张力（例：DxeNetLib.inf 是唯一 `LIBRARY_CLASS = NetLib` 实例，回退成功——见第五节 F4 的机制核实）。
- **d. `!include` 片段被整体跳过**：`!include NetworkPkg/NetworkLibs.dsc.inc`（OvmfPkgX64.dsc `:261`）、`!include MdePkg/MdeLibs.dsc.inc`（`:150`）等均被跳过（`edk2.ts:229` 只跳过 `!` 行）。`NetLib|NetworkPkg/Library/DxeNetLib/DxeNetLib.inf` 实际在 `NetworkPkg/NetworkLibs.dsc.inc:16`，不在任何 OvmfPkg DSC 顶层（见 F4）。
- **e. `$(...)` 宏路径不展开**：parseInfLight 不展开宏，而 Edk2Extractor 展开（6354773 轮已支持）。语料中 `CryptoPkg/Library/OpensslLib/OpensslLib.inf:30-…`（300+ 行 `$(OPENSSL_PATH)/…`）、`MdePkg/Library/BaseFdtLib/BaseFdtLib.inf:37-50`、`TcgTpmPkg/Library/TpmLib/TpmLib.inf:39+` 等实例的源文件无法映射 → 漏连（安全，退回正常解析）。
- **f. 多个 LIBRARY_CLASS 行只保留最后一行**：`MdePkg/Library/BaseLib/UnitTestHostBaseLib.inf:22-23` 声明 `LIBRARY_CLASS = BaseLib` 与 `LIBRARY_CLASS = UnitTestHostBaseLib|HOST_APPLICATION`，解析只留后者，BaseLib 归属丢失。`MdePkg/Library/BaseMemoryLibOptDxe/BaseMemoryLibOptDxe.inf:21` 与 `:68`（后者在 `[Defines.AARCH64]` 下）同名为 BaseMemoryLib，类名碰巧一致，但模块类型限制被丢弃、架构限定被无视。

---

## 二、框架通用性（语料验证）

### 2.1 已确认存在的形态（适配应覆盖，且多为**部分**覆盖）

| 形态 | 语料证据 | 桥的覆盖情况 |
|---|---|---|
| LIBRARY_CLASS 不带 MODULE_TYPES | MdePkg/Library 下 75 个 INF（ArmFfaMemMgmtLib、CpuLib、IoLib 等） | ✓ 解析正确 |
| `[Sources.common]`/`[Sources.Ia32]`/`[Sources.X64]` 架构分区 | BaseLib.inf、BaseMemoryLibOptDxe.inf | 部分：跨分区**同名函数**产生重复目标 → 误拒绝（F2） |
| DSC 无顶层 [LibraryClasses]、只有块内 `<LibraryClasses>` | OvmfPkgX64.dsc `:781-786`（SecMain 块内覆盖）等 | ✓ overrides 处理，但重复 [Components] 条目后者胜（F14，P3） |
| 无 DSC 只有 LIBRARY_CLASS 的迷你项目 | 机制存在（libClassInstances 回退） | 未测试（F12，P3） |
| `!if`/`!else` 条件映射 | OvmfPkgX64.dsc `:288-292` 等 | ✗ 双分支都收 → 歧义 |
| 模块类型分区 `[LibraryClasses.common.*]` | OvmfPkgX64.dsc、MdeModulePkg.dsc（见 1.2-a） | ✗ 合并 → 歧义 |
| `!include` 库片段 | NetworkPkg/NetworkLibs.dsc.inc、MdePkg/MdeLibs.dsc.inc、OvmfPkg/Include/Dsc/*.dsc.inc | ✗ 跳过 |
| 多平台 DSC 并存 | 语料 55 个 .dsc（OvmfPkg 有 OvmfPkgX64/Ia32/Ia32X64/Xen.dsc） | ✗ 全合并 → 歧义（F3） |
| 架构目录源文件（Ia32/、X64/） | BaseLib Ia32/*.c 与 X64/*.c 定义同名函数 | ✗ 重复目标（F2） |
| 宏路径源文件 | OpensslLib、BaseFdtLib、TpmLib | ✗ 跳过（1.2-e） |

### 2.2 通用性判定

- **对 tianocore 单平台 + 简单 DSC 成立**：提交的合成测试场景（单顶层 [LibraryClasses]、无 !include/无分区）与 OvmfPkgX64.dsc 中少数"顶层唯一映射"的类（BaseLib `:159`、NetLib 经回退等）能正确建边。
- **对真实 tianocore 树不成立**：只要索引里含任一真实平台/包 DSC（模块类型分区 + 条件行是常态），DebugLib / MemoryAllocationLib / PcdLib / HobLib / ReportStatusCodeLib / CpuExceptionHandlerLib 等常用类的所有调用都会歧义 → RefusedRef 删行（F1，P0）。MdeModulePkg.dsc 这类**包级** DSC（用户单独索引一个包时最常见）本身就含 10 个模块类型分区，足以触发。
- **对 edk2-staging / 厂商树 / edk2-platforms**：INF/DSC 语法同源（分区、条件、include 机制一致），因此同样受影响；edk2-platforms 大量使用 `!include` 片段与按平台拆分 DSC，问题更突出 `[INFERENCE]`（未实际索引，依据规格文档与 edk2 同构语法推断）。
- **非标准目录布局（INF 不在包内）**：`rel()` 按 INF 所在目录解析 [Sources]、DSC 行按工作区根解析——与 EDK2 规格一致，布局无关 ✓。`includeIndex` 的 `<pkg>/Include/…` 回退是既有代码（tianocore 布局假设），非本提交引入。

### 2.3 不能稳定完善的场景（不瞎做，明确列出）

1. **多 DSC 并存时"哪个 DSC 构建哪个模块"**：无任何声明能给出模块→平台归属（真实构建由命令行 `-p Platform.dsc` 决定）。全合并 + 唯一性是唯一无输入的策略，注定在多平台树上歧义。
2. **条件分支的实际选择**：`!ifdef $(FLAG)` 依赖构建参数，声明集合无法稳定判定。
3. **模块类型 / 架构过滤**：caller 的 MODULE_TYPE 与目标架构（`[LibraryClasses.common.PEIM]` 只对 PEIM 构建生效）需要构建上下文；INF 的 `MODULE_TYPE` 只能给出模块自身类型，不能确定实例侧模块类型约束的满足性。

**正确姿态**：对 1-3，桥应当"不建边（return null，行保留/置 failed）"，而不是 RefusedRef 删行（F1 的核心修复）。

---

## 三、与既有适配协同

### 3.1 RefusedRef 语义（行删除）用于库调用 —— **不一致（P0 核心）**

- DEC/UNI 声明集合治理（33a05dc）的 refused 对象是 **extract() 合成的候选 ref**（`references`、`fromNodeId === file:<path>`）：ref 本身没有真实目标，"名字未在 DEC/UNI 声明" = 候选不成立，删除合理。流水线注释也明示：`"Refused refs are deleted outright … a later file gaining the name can never make them valid"`（`src/resolution/index.ts:1213-1218`、`:1280-1291`）。
- 本提交把同一语义套到 **C 解析器发出的真实 `calls` ref** 上：`cands.length !== 1` 一律 refused（`edk2.ts:437-443`），包括"caller **已声明**类但实例歧义"（模块类型分区合并、条件行、多 DSC）与"函数在同实例多文件重复定义"（架构变体）——这些调用**真实存在且构建可链接**，refused 使整行被永久删除，增量 sync 无法恢复（同上注释）。对图工具而言，调用点从图中消失（`callers`/`impact` 查询无此调用）。
- **正确语义**：仅"名字只存在于库实例 + caller 未声明任何提供类"（本提交要防的错误边场景）才 refused；其余歧义/未匹配应 return null（走正常名匹配或置 failed 保留行）。这是 P0 的修复方案。

### 3.2 模块内同名遮蔽检查顺序 —— 正确但缺测试

先查 `moduleFunctions`（caller 自身 [Sources] .c 定义的函数）→ 命中则 return null 让正常解析连到模块自身函数（`edk2.ts:424`）→ 再查声明链。顺序正确（模块内定义优先）。但该检查只覆盖 [Sources] 的 .c/.cc/.cpp：caller 头文件中定义的 inline 同名函数不在此列 → 可能给库实例铸错边 `[INFERENCE]`（语料中 EDK2 头文件以原型为主，inline 定义少见，P3）。无测试覆盖此分支（F12）。

### 3.3 calls 边 confidence 0.9 —— 一致

### 3.4 CheckEdk2 验证通过的维度（补充）

- language 门稳定：grammars.ts:80 `.c`→'c'，calls ref 继承文件语言（store-writer.ts:59-60）——`ref.language === 'c'` 门稳定，F9（.cpp 漏连）属实但门本身无漂移。
- 协议调用安全：`gBS->AllocatePool` 类调用在 C 语法树中是 `gBS.AllocatePool` 字段访问（tree-sitter.ts:4430-4431），不会与库内函数名撞车，桥不受影响。
- 并发无撕裂：每 worker 单实例顺序执行，WeakMap 键为每实例 context 稳定；仅存在重复构建开销（并入 F12）。

（3.3 原文：edk2 框架既有取值：ENTRY_POINT 0.95、全局回退 0.85、路径/声明边 0.9；其他框架 0.6-1.0 区间。0.9 触发 `resolveOne` Strategy 1 短路（`src/resolution/index.ts:977-980`），与"声明链解析出的边"同级——一致 ✓。`createEdges` 对 calls→instantiates 的提升仅针对 class/struct 目标，库实例函数是 function，无副作用 ✓。

---

## 四、交付完整性

| 项 | 结论 |
|---|---|
| CHANGELOG.md | **未记录**库调用桥。EDK2 条目（`CHANGELOG.md:18`）枚举的能力清单（ENTRY_POINT、DEC 解析、PCD、DSC [LibraryClasses]→INF 等）不含"C 调用 → 库实例函数"。整块仍在 [Unreleased]，单条 feature 文本未更新 → P3。 |
| edk2.ts 顶部 docstring | 已更新且大体准确（"returns references/imports edges plus library-CALL bridges"），但**自相矛盾**：`edk2.ts:31-34` 声称 "`LibPcdGet32` stays a normal name resolution"——实测 `LibPcdGet32` 定义于 `BasePcdLibNull/PcdLib.c:91`、`PeiPcdLib/PeiPcdLib.c:186`、`DxePcdLib/DxePcdLib.c:193` 三个 PcdLib 实例，且 PcdLib 在 OvmfPkgX64.dsc 多分区映射（`:154/:359/:389/:392`）→ 桥会 refuse 它而非"正常名解析"（F5，P2）。 |
| commit message | 机制描述（声明链、遮蔽、非模块代码、多实例歧义不建边）与代码相符；但**验证路径不实**："OvmfPkg DSC NetLib\|NetworkPkg/Library/DxeNetLib/DxeNetLib.inf" 不存在于 OvmfPkgX64.dsc（NetLib\| 在 `!include` 的 `NetworkPkg/NetworkLibs.dsc.inc:16`，解析器跳过），实际成功路径是**唯一 LIBRARY_CLASS 回退**（F4，P2）；"115k+ unresolved calls"未在本审查中复算（需全量索引，标 `[unverified]`）；"Unit + integration tests cover declared/unrelated/undeclared/**ambiguous** callers"——无歧义测试（F12，P3）。 |
| 测试断言 | 全部有断言（76 测试通过：`edk2-resolution.test.ts` 44、`edk2-index-integration.test.ts` 32；含真实 edge 断言 `expect(edges.some(...)).toBe(true)`）。✓ 但覆盖面是合成迷你项目（单 DSC、无分区/无条件/无 include），不反映语料现实，P0/P1 场景全部未覆盖。 |

---

## 五、发现清单

> 标注来源：R=ReportEdk2（本报告）；C=CheckEdk2（发现已通过 hub 合并，见文末说明）。行号均为 `src/resolution/frameworks/edk2.ts` 当前文件（HEAD=e364674）。

### P0

**F1. 实例歧义（模块类型分区 / 条件行 / 多 DSC 合并）导致合法库调用被 RefusedRef 永久删行** `[R]+[C]`
- 触发：`parseInfLight`/DSC Pass 2 将 `[LibraryClasses.common.*]` 分区与 `!if/!else` 分支全部合并进 `defaultInstances`（`:226`、`:298`、`:229`）；`effectiveInstance` 在 `dsc.length > 1` 时返回 null（`:429-430`）；`cands.length !== 1` 一律 `return refused(...)`（`:437-443`）；流水线对 refused 永久删行（`src/resolution/index.ts:1213-1218`、`:1280-1291`）。
- 语料证据（[R]）：OvmfPkgX64.dsc DebugLib 10+ 分区映射；MdeModulePkg.dsc MemoryAllocationLib 6 个实例；语料 55 个 .dsc 同类不同映射（BaseMemoryLib：OvmfPkgX64.dsc:158 → RepStr，MdeModulePkg.dsc:38 → 基础版）。直接调用点：MdeModulePkg 内 `AllocatePool (` 调用 100+ 处（如 `Bus/Spi/SpiNorFlashJedecSfdp/SpiNorFlashJedecSfdp.c:1736`）。
- 量化证据（[C]，CheckEdk2 复刻 parseInfLight+pass2 对全语料统计）：95 个类在 DSC 桶里有多条目 + 75 个仅靠 LIBRARY_CLASS 回退的歧义类——TimerLib 15、ResetSystemLib 12、BaseCryptLib 11、DebugLib 10、MemoryAllocationLib 10、SerialPortLib 10、HobLib 9、DevicePathLib 4（MdeModulePkg.dsc:25-189 中 HobLib 在 PEI_CORE/DXE_CORE/DXE_DRIVER 等 7 节分别映射 PeiHobLib/DxeCoreHobLib/DxeHobLib；OvmfPkgX64.dsc:152-540 中 DebugLib/HobLib 各 3 个不同实例）。关键性质（[C]）：这与函数名唯一性无关——即使某函数名只在一个实例里定义，类级歧义照样拒绝。
- 影响：真实 EDK2 树上最常用库（MemoryAllocationLib/DebugLib/PcdLib/HobLib 等）的所有直接调用行被删，图中调用点消失且增量 sync 无法恢复；与提交目标（解析库调用）直接相悖。EDK2 驱动多以 `DEBUG ((...))` 宏输出（`NetworkPkg/IScsiDxe/IScsiMisc.c:872` 等，宏不被解析为 calls ref），故 DebugPrint 宏不触发；但 AllocatePool/CopyMem/SetMem/ZeroMem/DevicePathFromHandle 等直接调用广泛存在。
- 修复：歧义/未匹配 → return null；仅"名字只在库实例 + caller 未声明任何提供类"→ refused。可选增强：按 caller 模块 INF 的 MODULE_TYPE 过滤分区、解析 `!ifdef/!else/!endif` 嵌套。
- `file_path`: `src/resolution/frameworks/edk2.ts`, `line_start` 437, `line_end` 443。

### P1

**F2. 同一实例跨架构源文件重复定义同名函数 → 合法调用被 refused** `[R]+[C]`
- 触发：BaseLib `[Sources.Ia32]` 与 `[Sources.X64]` 都列 `.c`（`MdePkg/Library/BaseLib/BaseLib.inf`）；`X64/CpuBreakpoint.c:29` 与 `Ia32/CpuBreakpoint.c:29` 均定义 `CpuBreakpoint`；`X64/GccInline.c` 与 `Ia32/GccInline.c` 均定义 `MemoryFence`/`CpuPause`/`AsmReadEflags`/`AsmReadMm0-7` 等。 另（[C]）：`Ia32/WriteMsr64.c` 与 `X64/WriteMsr64.c` 均定义 `AsmWriteMsr64`（同 className=BaseLib、同 infPath）→ 单实例即中招。`fns` 得到同 class+infPath 的 ≥2 目标 → `cands.length ≥ 2` → refused。注意 Pass 3 的 `seen` 去重（`:373-376`）只覆盖同一文件在多分区重复列出（如 BaseMemoryLibOptDxe `[Sources.Ia32]`+`[Sources.X64]` 都列 MemLibGuid.c），**不**覆盖跨文件同名。
- 影响：声明了 BaseLib 的模块调用 `CpuBreakpoint`/`CpuPause`/`MemoryFence` 等（断言/自旋锁路径常见）即删行（[C] 实测 CpuBreakpoint 有 5 个调用方 .c）。CheckEdk2 定级 P0（即使 DSC 对 BaseLib 单映射也拒绝）；本报告列 P1 因其触发面窄于 F1，修复极简：按 `(className, infPath)` 对 targets 去重后再判唯一。
- `file_path`: `src/resolution/frameworks/edk2.ts`, `line_start` 434, `line_end` 439。

**F3. 多 DSC 合并：同类映射到不同实例 → 全树/多平台索引普遍歧义** `[R]`
- 触发：DSC Pass 2 把所有 `.dsc` 模块节点的 `[LibraryClasses]` 合并进同一个 `defaultInstances`（无平台归属）；语料 55 个 .dsc，BaseMemoryLib/BaseLib/DebugLib 等在平台间映射不同实例 → 歧义 → refused。任何"无法从声明稳定完善"（见 2.3-1），正确姿态是歧义时 return null。
- `file_path`: `src/resolution/frameworks/edk2.ts`, `line_start` 429, `line_end` 432。

**F4a. `!include` 片段被跳过后，「多实例类」回退唯一 LIBRARY_CLASS 仍歧义** `[C]`
- 54 个 DSC 使用 `!include`（[C] 统计）；其中 43 个 `!include MdePkg/MdeLibs.dsc.inc`（内含真实 `[LibraryClasses]`：SafeIntLib/CpuLib/SynchronizationLib/StackCheckLib…），OvmfPkg 还 include ShellLibs.dsc.inc（`ShellLib|UefiShellLib.inf` 等）。另（[C]）：`OvmfPkg/Include/Dsc/NetworkComponents.dsc.inc:46-48` 中 IScsiDxe 的组件级 `<LibraryClasses>` 覆盖同样丢失。跳过片段后类无 DSC 桶 → 回退 LIBRARY_CLASS 唯一性；多实例类（StackCheckLib：StackCheckLib+StackCheckLibNull；CpuLib：BaseCpuLib+BaseCpuLibNull）→ 歧义 refused。与 1.2-d / F1 同根，独立列出以强调「跳过声明片段」的普遍影响。
- `file_path`: `src/resolution/frameworks/edk2.ts`, `line_start` 229, `line_end` 229。

### P2

**F4. commit message 验证路径不实：NetLib 映射不在 OvmfPkg DSC，在被跳过的 !include 片段** `[R]+[C]`
- `NetLib|NetworkPkg/Library/DxeNetLib/DxeNetLib.inf` 在 `NetworkPkg/NetworkLibs.dsc.inc:16`（被 OvmfPkgX64.dsc:261 `!include`，解析器跳过）；OvmfPkgX64.dsc 无该行。（[C] 独立 grep 确认 OvmfPkg 全部 dsc 中 `NetLib|` 零命中）。实际成功路径是唯一 LIBRARY_CLASS 回退（`DxeNetLib.inf:19` 是唯一 `LIBRARY_CLASS = NetLib` 实例）。验证叙事与实现机制不符（端到端结果 IScsiDxe→NetLibGetMacAddress 属实：`NetworkPkg/IScsiDxe/IScsiDxe.inf:75`、`DxeNetLib.c:2251`、`IScsiMisc.c:622/734/1890`）。
- `file_path`: `src/resolution/frameworks/edk2.ts`, `line_start` 431, `line_end` 432。

**F5. docstring 自相矛盾：LibPcdGet32 会被桥 refuse，非"normal name resolution"** `[R]`
- `edk2.ts:31-34` 声称 "`LibPcdGet32` stays a normal name resolution"；但 LibPcdGet32 定义于 3 个 PcdLib 实例（见上），PcdLib 多分区映射 → cands=0 → refused 删行。docstring 需改写。
- `file_path`: `src/resolution/frameworks/edk2.ts`, `line_start` 31, `line_end` 34。

**F6. RefusedRef 语义跨种类误用（与 33a05dc 不一致）** `[R]`
- 33a05dc 的 refused 对象是无真实目标的合成候选；本提交用于真实 calls ref（详见 3.1）。语义需区分；另 refused 的 reason 文本在"已声明类但实例歧义"时谎报 "caller module declares none of the providing classes"（`:440-443`），误导诊断。（[C] 独立确认 P1-4：cands=0 时消息称 declares none，实际 caller 声明了该类，只是类级歧义）。
- `file_path`: `src/resolution/frameworks/edk2.ts`, `line_start` 440, `line_end` 443。

**F7. 多 LIBRARY_CLASS 行只保留最后一行；[Defines.ARCH] 的 LIBRARY_CLASS 覆盖被当普通 [Defines]** `[R]`
- `UnitTestHostBaseLib.inf:22-23`（BaseLib 归属丢失）；`BaseMemoryLibOptDxe.inf:21/:68`（架构限定与模块类型限制丢弃，类名碰巧一致才未出错）。语料 11 个 INF 含 2 行 LIBRARY_CLASS。另（[C]）：`CryptoPkg/Library/BaseCryptLibOnProtocolPpi/Dxe/Pei/Smm/StandaloneMmCryptLib.inf` 同时声明 `BaseCryptLib|…` 与 `TlsLib|…`，解析只留 TlsLib → 声明 BaseCryptLib 的调用者 cands=0 refused。
- `file_path`: `src/resolution/frameworks/edk2.ts`, `line_start` 230, `line_end` 240。

**F8. [Sources] `$(...)` 宏路径不展开 → 大型第三方库实例漏连** `[R]`
- OpensslLib（300+ 文件）、BaseFdtLib、MipiSysTLib、TpmLib 等实例的源文件映射失败（安全漏连，退回正常解析）；与 Edk2Extractor 的宏展开（6354773）不一致。
- `file_path`: `src/resolution/frameworks/edk2.ts`, `line_start` 241, `line_end` 246。

**F13a. `rel()` 不归一化 `..` 路径 → 跨目录共享源漏连** `[C]`
- `rel()`（edk2.ts:224-228）仅做目录拼接与反斜杠替换，不解析 `..`：ManageabilityPkg 的 Pei/Dxe/Smm 共享 `../Common/*.c`、各 GoogleTest INF 使用 `../` 源文件 → fileModules/实例索引全部 miss（漏连不误杀）。修复：路径规范化（posix.normalize）。
- `file_path`: `src/resolution/frameworks/edk2.ts`, `line_start` 224, `line_end` 228。

**F13b. 共享 .c 跨模块时归属按先处理模块生效** `[C]`
- Pass 1 对同一 .c 被多个模块 [Sources] 引用时 `entry.moduleInf` 取先处理模块、classes 取并集（edk2.ts:273-275）→ 模块内遮蔽检查与 per-component override 可能按错误模块生效（部分被 F13a 掩盖）。
- `file_path`: `src/resolution/frameworks/edk2.ts`, `line_start` 273, `line_end` 275。

**F13c. 实例内 STATIC 函数可被选为目标** `[C]` `[INFERENCE]`
- Pass 3 无 visibility 过滤（edk2.ts:358-364），库实例内的 static 函数也能成为 0.9 边目标——对不可链接符号铸边；频率低。
- `file_path`: `src/resolution/frameworks/edk2.ts`, `line_start` 358, `line_end` 364。

### P3

- **F9. `.cpp` 调用不走桥**（`ref.language === 'c'`，`:409`）：GoogleTest host/EmulatorPkg 等 C++ 模块漏连（安全）。`[R]`
- **F10. CHANGELOG.md 未记录库调用桥**（`CHANGELOG.md:18` 能力清单缺此项）。`[R]`
- **F11. 测试覆盖缺口**（[R]+[C]）：现有 4 单测 + 2 集成只覆盖单映射 happy path / 未声明类拒绝 / 无命中 null；缺多条目桶、同实例多文件、组件 override、LIBRARY_CLASS 回退（真实 NetLib 路径！）、模块内遮蔽、!include、`..`/共享源、双 LIBRARY_CLASS、非 c 调用方用例；且集成测试 2（无边断言）无法区分 refused-deleted 与 unresolved（[C]）。commit message 声称覆盖 ambiguous callers 不实。`[R]+[C]`
- **F12. 性能**：首个命中 library call 同步全量构建（[C] 实测计数：pass1 10,972 次 getNodesInFile + pass3 9,382 次 + 2,268 次 readFile + 2×getNodesByKind('module')），单次 resolveOne 内同步阻塞；且每 resolver 实例/每 worker（池最多 6，resolver-pool.ts:105-109）各建一份，单次 run 最多 7 份，nodeCache 随之膨胀（[C]）。WeakMap 缓存后每 context O(1)/ref，与既有 declaredSets/includeIndex 模式一致；并发无撕裂（每 worker 单实例顺序执行，[C] 验证）。`[R]+[C]`
- **F13. 重复 [Components] 条目 override 后者胜**：OvmfPkgX64.dsc:831/841 的 CpuMpPei 两次（不同 FILE_GUID），MpInitLib 覆盖取第二次；`[Components.X64]` 架构分区合并——边缘情况。`[R]`
- **F14. `moduleFunctions` 遮蔽检查不覆盖 [Sources] 中列出的头文件函数**（sources 过滤仅 .c/.cc/.cpp，`:240`）——头文件 inline 同名函数遮蔽库名时可能铸错边 `[INFERENCE]`（语料中少见）。`[R]`

---

## 六、明确局限（不能稳定完善，不瞎做）

见 2.3 三条：多 DSC 平台归属、条件分支实际选择、模块类型/架构过滤。均需构建配置输入（命令行 `-p`、`-D`、`-a`），仅凭声明集合无法稳定判定。**这些场景的正确处理是"不建边、保留行"（return null），而非 RefusedRef 删行。** 其余可稳定完善项（分区拆分、条件解析、!include 展开、宏展开、架构去重、多 LIBRARY_CLASS）均有明确的声明来源，属"该做未做"而非"做不到"。

---

## 七、建议

1. **P0 必修**：把 `cands.length !== 1` 的 refused 拆分为——(a) 名字只在库实例且 caller 未声明任何提供类 → refused（防错误边，保留提交的安全意图）；(b) 已声明类但实例歧义/多目标 → return null（保留行，交正常解析或置 failed）。顺带修 reason 文案。
2. **P1 必修**：targets 按 `(className, infPath)` 去重（修 F2，改动极小）；多 DSC 合并至少注明"仅唯一映射时建边"（F3 与 F1 同修复）。
3. **P2 建议**：解析 `!ifdef/!else/!endif`（或至少对条件块整体跳过而非双收）；支持 `!include` 递归（解析器侧已有 include 链经验）；parseInfLight 与 Edk2Extractor 共享宏展开；LIBRARY_CLASS 收集全部行。
4. **测试**：补歧义、模块本地遮蔽、无-DSC 回退、架构变体、!include、多分区用例（对照语料 OvmfPkgX64.dsc 真实形态构造 fixture）。
5. **文档**：CHANGELOG 补记桥；docstring 修正 LibPcdGet32 例；commit message 修正验证路径描述。

---

## 附：CheckEdk2 发现并入说明

本报告由 ReportEdk2 撰写并汇总。CheckEdk2（正确性 lens）两轮发现均已合并：P0-1（类级歧义误杀）↔ F1；P0-2（同实例多文件同名）↔ F2；P1-3（!include 跳过）↔ F4a；P1-4（拒绝理由谎报）↔ F6；多 LIBRARY_CLASS 补充证据 ↔ F7；性能实测 ↔ F12；测试缺口 ↔ F11；`..` 路径、共享源归属、static 目标 ↔ F13a/F13b/F13c。双方独立验证，总体判定一致：incorrect（P0 需修复）。CheckEdk2 验证通过的维度（language 门、协议调用安全、并发无撕裂）已并入 3.3 节。
