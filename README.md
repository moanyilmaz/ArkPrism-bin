# ArkPrism

**ArkPrism** 是一款针对 OpenHarmony / HarmonyOS 应用二进制（`.hap` 包）的隐私 API 检测工具。

它直接从编译产物（ArkTS 字节码 `.abc` 和 Native 库 `.so`）中分析隐私敏感 API 的调用行为，**无需应用源代码**。

---

## 目录

- [核心能力](#核心能力)
- [技术原理](#技术原理)
- [项目结构](#项目结构)
- [快速开始](#快速开始)
- [运行模式详解](#运行模式详解)
- [输入输出格式](#输入输出格式)
- [配置规则](#配置规则)
- [各模块详解](#各模块详解)
- [常见问题](#常见问题)

---

## 核心能力

| 能力 | 说明 |
|------|------|
| **ArkTS 字节码分析** | 解析 `.abc` 文件，用规则匹配隐私 API 调用 |
| **Native 库分析** | 用 angr 符号执行扫描 `.so` 文件中的隐私 Native API |
| **调用链构建** | 基于 Andersen PTA 构建从入口到敏感 API 的完整调用路径 |
| **数据流分析** | 基于 IFDS 追踪隐私数据从 source 到 sink 的流向 |
| **多源联合检测** | 检测"同一方法内多种敏感数据被组合访问"的隐蔽行为 |
| **CFG 可达性过滤** | 用控制流图过滤死代码/不可达路径中的误报 |
| **置信度评级** | 每个命中标注 high/medium/low confidence |

---

## 技术原理

### 1. 为什么可以分析二进制？

OpenHarmony 应用编译后会生成 `.abc`（ArkTS 字节码）文件和 `.so`（Native 库）文件：

```
.hap 包结构（解压后）
├── ets/                    # ArkTS 字节码
│   └── modules.abc         # 包含所有 ArkTS 代码的字节码
├── libs/                   # Native 库
│   └── libvideoCompressor.so
└── resources/              # 资源文件
```

- **`.abc` 文件**：包含了 ArkTS 编译后的中间表示（IR），包含函数调用、控制流、对象访问等信息
- **`.so` 文件**：包含了动态链接的 C/C++ 原生 API 符号

ArkPrism 直接解析这些编译产物，不需要源代码。

### 2. ArkTS 分析流水线

ArkTS 分析是整个工具的核心，分为以下几个阶段：

```
HAP 目录
  │
  ├─ 提取所有 .abc 文件
  │
  ├─ Stage.createHiFile()   ← 华为分析工具解析字节码
  │     │
  │     ├─ HiFile (顶层文件)
  │     │    └─ List<HiFunction> (所有函数)
  │     │         └─ Body (函数体)
  │     │              └─ List<Stmt> (语句)
  │     │
  │     ├─ getAllStmtApiNameMap()  → Map<Stmt, "namespace.method">
  │     └─ getAllStmtFieldNameMap() → Map<Stmt, "namespace.field">
  │
  ├─ 规则匹配
  │     ├─ directRules (directCall=true) → 精确匹配 namespace.method
  │     ├─ indirectRules (directCall=false) → 后缀匹配 .method
  │     └─ constantRules (directCall=null) → 常量字段匹配
  │
  ├─ CFG 可达性检查
  │     └─ isReachableFromEntry() → 过滤死代码
  │
  ├─ 调用链构建
  │     ├─ Stage.createCallGraph(ANDERSEN) → 指针分析构建调用图
  │     └─ CallGraphExplorer.traceBackwards() → DFS 反向追溯到入口
  │
  ├─ 数据流分析（可选）
  │     ├─ Stage.createICFG() → 构建过程间控制流图
  │     └─ TaintAnalysis → IFDS 污点分析（source→sink）
  │
  └─ 生成 UnifiedPrivacyReport
```

#### 2.1 华为分析工具 API

ArkPrism 依赖华为的 `hisec-enhance-app-analyzer` 库提供的基础 API：

| API | 作用 |
|-----|------|
| `Stage.createHiFile(path, ARKTSV1)` | 解析 `.abc` 文件为 HiFile |
| `Stage.createCallGraph(hiFile, ANDERSEN)` | 构建基于指针分析的调用图 |
| `Stage.createOrGetStmtGraph(func)` | 构建语句级 CFG |
| `hiFile.getAllStmtApiNameMap()` | 获取所有语句的 API 调用名称 |
| `BlockGraph.createOrGetGraph(func)` | 构建基本块级 CFG |
| `TaintAnalysis.createTaintAnalysisByStmt()` | 创建 IFDS 污点分析任务 |

#### 2.2 规则匹配策略

ArkPrism 使用三种策略匹配隐私 API：

**directRules（直接调用，directCall=true）**
```
匹配条件：语句中的 namespace 必须精确等于规则中的 namespace，且紧随其后的是 method
例如：geoLocationManager.getCurrentLocation()
      ↑ namespace           ↑ method
```

**indirectRules（间接调用，directCall=false）**
```
匹配条件：语句路径的末尾方法名以规则 method 结尾
用于：链式调用、中间有前缀的情况
例如：someObj.geoLocationManager.getCurrentLocation() → 匹配 geoLocationManager.getCurrentLocation
```

**constantRules（常量字段，directCall=null）**
```
匹配条件：语句是字段访问，且最后一级字段名等于规则 method
用于：常量定义为隐私字段的场景
例如：wifiManager.SCAN_RESULTS → 匹配 wifiManager.SCAN_RESULTS
```

#### 2.3 CFG 可达性过滤

某些隐私 API 出现在死代码中（如 catch 块中永不执行的代码），ArkPrism 用控制流图过滤：

```java
// isReachableFromEntry() 算法：
1. 用 BlockGraph 判断语句所在基本块是否可达
2. 若不可达 → confidence = "low"
3. 若可达 → 进入下一步分析
```

### 3. Native SO 分析流水线

Native 分析通过 angr 符号执行完成：

```
SO 文件 (libxxx.so)
  │
  ├─ angr.Project() → 加载 ELF
  │     │
  │     ├─ analyze_import_symbols()
  │     │     ├─ 解析 ELF 导入表 (imports)
  │     │     ├─ 过滤系统符号 (libc, pthread 等)
  │     │     └─ 精确匹配规则 symbol → import_symbol (高置信度)
  │     │
  │     └─ analyze_string_references()
  │           ├─ 扫描 .rodata/.data 节中的字符串
  │           ├─ 完整 token 匹配（避免子串误匹配）
  │           └─ 规则 symbol 匹配 → string_reference (中/低置信度)
  │
  └─ 输出 JSON 命中列表
```

#### 3.1 两种匹配模式的区别

| 模式 | 含义 | 置信度 | 说明 |
|------|------|--------|------|
| `import_symbol` | 导入表精确匹配 | high | SO 确实链接了该符号，运行时一定会加载 |
| `string_reference` | 字符串引用 | medium/low | 字符串出现在数据段，可能被动态加载 |

#### 3.2 扫描范围

angr 只扫描以下节（避免误报）：
- `.rodata` — 只读数据段（字符串常量）
- `.data` — 可读写数据段
- `.dynstr` — 动态链接字符串表

跳过的节：
- `.debug_*` — 调试信息（包含大量无关符号名）
- `.text` — 代码段（符号名嵌入不可靠）
- `.strtab` — 字符串表（误报率高）

### 4. 多源联合检测原理

隐私合规中，一种常见的高风险场景：**应用同时获取多种敏感数据并组合使用**。

例如：设备标识 + 位置信息 + WiFi 信息 → 用于用户画像/广告定向

```
一个方法中同时调用了：
  deviceInfo.productModel   → 设备型号（硬件ID类）
  geoLocationManager.getCurrentLocation → 当前地理位置
  wifiManager.getScanInfoList → 周围 WiFi 列表

→ 这是一个"多源联合"的隐蔽数据采集行为
```

ArkPrism 通过 `profile_combinations.json` 定义组合规则，然后在分析报告中标记此类行为。

### 5. dataDirection 语义

每个隐私 API 规则都有一个 `dataDirection` 字段，指明数据流向：

| 值 | 含义 | 例子 |
|----|------|------|
| `source` | **读取**隐私数据（数据源） | `getDeviceId()` 读取设备ID |
| `sink` | **输出/存储**隐私数据（数据汇） | `httpRequest()` 上传数据 |
| `both` | 既读又写 | `file.open()` 打开文件 |
| `excluded` | 非隐私相关，跳过检测 | `getOsVersion()` 读版本号 |

---

## 项目结构

```
ArkPrism/
├── src/main/java/com/huawei/hisec/
│   ├── Main.java                          # 程序入口，批量/单应用分析入口
│   ├── PreciseSensitiveApiScanner.java    # ArkTS 字节码分析核心
│   ├── SoVulnerabilityScanner.java        # Native SO 分析核心
│   ├── CallGraphExplorer.java             # 调用链构建（Andersen PTA）
│   ├── DataFlowExplorer.java              # 数据流分析（IFDS 污点追踪）
│   ├── MultiSourceCollaborationAnalyzer.java  # 多源联合检测
│   ├── PrivacyCatalog.java                # Source/Sink 目录加载
│   ├── AliasAnalyzer.java                 # 指针分析别名检测
│   └── UnifiedPrivacyReport.java          # 统一报告数据结构
│
├── config/
│   ├── privacy_apis.json        # ArkTS 隐私 API 规则（199条）
│   ├── native_privacy_apis.json # Native 隐私 API 规则（235条）
│   └── profile_combinations.json # 多源联合检测规则
│
├── angr/
│   └── pure_angr_scanner.py     # angr 符号执行扫描 SO
│
└── pom.xml                      # Maven 构建配置
```

### 各文件职责

| 文件 | 职责 |
|------|------|
| `Main.java` | 入口：发现 HAP 目录、协调 ArkTS + SO + 多源联合三大阶段 |
| `PreciseSensitiveApiScanner.java` | ArkTS 分析：解析 ABC → 规则匹配 → 调用链 → 数据流 |
| `SoVulnerabilityScanner.java` | SO 分析：调用 Python/angr、转换结果 |
| `CallGraphExplorer.java` | 调用链：从 sink 函数反向 DFS 追溯到入口 |
| `DataFlowExplorer.java` | IFDS 数据流：source → sink 污点追踪 |
| `MultiSourceCollaborationAnalyzer.java` | 多源联合：规则匹配 same_method / lca / same_file |
| `PrivacyCatalog.java` | 加载 privacy_apis.json 中的 source/sink 目录 |
| `AliasAnalyzer.java` | 包装华为 Andersen PTA 做别名分析 |
| `UnifiedPrivacyReport.java` | 报告数据结构（JSON 模型） |

---

## 快速开始

### 前置条件

| 依赖 | 说明 |
|------|------|
| JDK 17+ | 运行 Java 程序 |
| Maven 3.6+ | 构建项目 |
| WSL + angr | 仅分析 SO 时需要 |

需要华为内部工具：
- `hisec-enhance-app-analyzer-all-in-one-*.jar` → 放入 `lib/` 目录

### 编译

```bash
cd ArkPrism
mvn clean compile -DskipTests
```

### 准备输入

将待分析的 HAP 包**解压**后的目录放入 `input/`：

```
input/
├── app1_C6917602215994202990_1.0.0/
│   ├── ets/modules.abc
│   ├── libs/arm64-v8a/libvideoCompressor.so
│   └── ...
└── app2_C6917602221479724885_1.0.0/
    └── ...
```

> **注意**：`input/` 目录下的每个子目录被视为一个独立的 HAP 应用。

### 运行分析

**方式一：批量分析（IDEA 点击运行 Main.java）**

默认参数：`input/` `config/privacy_apis.json` `out/` `config/profile_combinations.json` `config/native_privacy_apis.json`

**方式二：命令行**

```bash
mvn exec:java -Dexec.mainClass="com.huawei.hisec.Main" \
  -Dexec.args="input/ config/privacy_apis.json out/ config/profile_combinations.json config/native_privacy_apis.json"
```

**方式三：只分析 ArkTS**

```bash
mvn exec:java -Dexec.mainClass="com.huawei.hisec.PreciseSensitiveApiScanner" \
  -Dexec.args="input/app1/ config/privacy_apis.json out/arkts_scan_debug.json"
```

**方式四：只分析 SO**

```bash
# 先复制 Python 脚本到 WSL
cp angr/pure_angr_scanner.py ~/arkprism/

# 设置环境变量
set ARKPRISM_WSL_SCANNER=/mnt/d/Projects/ArkPrism/angr/pure_angr_scanner.py

# 运行
mvn exec:java -Dexec.mainClass="com.huawei.hisec.SoVulnerabilityScanner" \
  -Dexec.args="input/app1/ out/native_scan_debug.json config/native_privacy_apis.json"
```

### 查看结果

```
out/
└── batch_20260526_154619/           # 批量模式（有多个 HAP 时）
    ├── app1_C6917602215994202990_1.0.0/
    │   └── app1_C6917602215994202990_1.0.0_privacy_report.json
    ├── app2_C6917602221479724885_1.0.0/
    │   └── app2_C6917602221479724885_1.0.0_privacy_report.json
    ├── arkprism_20260526_154619.log
    └── batch_summary.json           # 批量汇总

# 单应用模式（只有一个 HAP 时）
out/
└── app1_C6917602215994202990_1.0.0_20260526_154619/
    ├── app1_C6917602215994202990_1.0.0_privacy_report.json
    └── arkprism_20260526_154619.log
```

---

## 运行模式详解

### 批量模式 vs 单应用模式

**自动判断规则：**

```
扫描 input/ 目录的第一层子目录
├─ 若有子目录含 .abc 或 .so → 批量模式
└─ 否则，若 input/ 本身含 .abc 或 .so → 单应用模式
```

**批量模式：** `input/` 下有多个 HAP 子目录时，每个子目录分别分析，输出 `batch_summary.json` 汇总。

**单应用模式：** 直接传入一个 HAP 目录路径时，该目录视为单一应用。

### 内部目录过滤

ArkPrism 会跳过 HAP 的常见内部子目录，避免误识别：

```
input/
├── app1/                    ← HAP 子目录 ✓
│   ├── ets/                 ← 内部目录 ✗
│   ├── libs/                ← 内部目录 ✗
│   ├── resources/           ← 内部目录 ✗
│   └── entry/               ← 内部目录 ✗
└── app2/                    ← HAP 子目录 ✓
```

过滤的目录名：`ets`、`libs`、`lib`、`resources`、`res`、`assets`、`entry`、`src`、`oh_modules`、`node_modules`

---

## 输入输出格式

### 报告完整结构

以下是一个完整 `privacy_report.json` 的字段说明：

```json
{
  // ==================== 基本信息 ====================
  "schemaVersion": "1.0",           // 报告格式版本
  "analysisMode": "binary",         // 分析模式（binary = 二进制分析）
  "projectName": "C6917602215994202990_1.0.0",  // HAP 名称
  "projectDirectory": "/path/to/input/C6917602215994202990_1.0.0",
  "analysisTimestamp": "2026-05-26T15:46:19.123+0800",

  // ==================== 隐私 API 命中列表 ====================
  "privacyApiUsages": [
    {
      "sourceLayer": "ArkTS",       // "ArkTS" 或 "Native"
      "sourceKind": "API_MAP",      // ArkTS: API_MAP / FIELD_MAP
                                    // Native: ELF_IMPORT / ELF_STRING
      "category": "direct invoke stmt after assignment",
                                    // 命中分类
      "apiPackage": "@kit.BasicServicesKit",
      "namespace": "deviceInfo",
      "method": "productModel",
      "args": [],                   // 从语句中提取的参数
      "code": "VirtualCall: %0.<deviceInfo.productModel>",
                                    // 原始 IR 语句
      "file": "modules.abc",        // 来源文件
      "declaringMethod": "MyComponent:aboutToAppear()",
                                    // 所在函数
      "permission": null,           // 所需权限（若有）
      "profilingCategory": "device_identity.hardware",
                                    // 分析类别
      "dataDirection": "source",    // source / sink / both
      "confidence": "high"          // high / medium / low
    }
  ],

  // ==================== 调用链（ArkTS 专有） ====================
  "callChains": [
    {
      "apiUsageIndex": 0,            // 指向 privacyApiUsages[index]
      "entryMethod": {
        "name": "MyComponent:aboutToAppear()",
        "type": "component_lifecycle", // component_lifecycle / ability_lifecycle
                                       // ui_component / event_handler / async_callback
        "file": "modules.abc",
        "line": -1
      },
      "chain": [
        {
          "caller": "MyComponent:aboutToAppear()",
          "callee": "getDeviceInfo()",
          "callType": "lifecycle_init"
        },
        {
          "caller": "getDeviceInfo()",
          "callee": "deviceInfo.productModel",
          "callType": "direct"
        }
      ],
      "sourceSnippets": [
        {
          "method": "aboutToAppear()",
          "file": "modules.abc",
          "code": "VirtualCall: %0.<deviceInfo.productModel>\n..."
        }
      ],
      "dataSinks": [
        {
          "sinkType": "network",   // network / storage / log / clipboard / unknown
          "sinkApi": "@ohos:net.http.request",
          "sinkMethod": "request()",
          "sinkFile": "modules.abc",
          "sinkLine": 42
        }
      ],
      "semanticContext": {
        "pageName": "MyPage",
        "componentClass": "MyComponent",
        "semanticAnchor": "MyComponent:aboutToAppear()",
        "simplifiedChain": "aboutToAppear() -> getDeviceInfo() -> productModel()",
        "purposeHint": "In modules.abc, function aboutToAppear() calls productModel, data flows to network(request)"
      }
    }
  ],

  // ==================== 多源联合检测 ====================
  "multiSourceCollaborations": [
    {
      "ruleId": "DEVICE_LOCATION_WIFI",
      "ruleName": "设备+位置+WiFi联合",
      "detectionLevel": "same_method", // same_method / lca / same_file
      "lcaMethod": "onButtonClick()",  // 共同祖先方法
      "categories": ["device_identity.hardware", "location", "network.wifi"],
      "apis": [
        {"apiUsageIndex": 0, "api": "deviceInfo.productModel"},
        {"apiUsageIndex": 5, "api": "geoLocationManager.getCurrentLocation"},
        {"apiUsageIndex": 8, "api": "wifiManager.getScanInfoList"}
      ],
      "riskLevel": "high",
      "confidence": "high",
      "reason": "Rule-match same_method: 设备+位置+WiFi联合 requires 3 conditions; matched 3 APIs."
    }
  ],

  // ==================== 统计汇总 ====================
  "summary": {
    "totalApiUsages": 15,
    "arktsApiUsages": 12,
    "nativeApiUsages": 3,
    "callChainCount": 8,
    "multiSourceCollaborationCount": 2,
    "analyzedAbcCount": 3,
    "analyzedSoCount": 7,
    "warnings": []
  }
}
```

---

## 配置规则

### privacy_apis.json（ArkTS 规则）

**文件位置：** `config/privacy_apis.json`

**结构：**

```json
[
  {
    "systemPackage": "@kit.BasicServicesKit",
    "category": "device_identity",
    "privacyApis": [
      {
        "namespace": "deviceInfo",
        "method": "productModel",
        "directCall": true,
        "permission": null,
        "profilingCategory": "device_identity.hardware",
        "dataDirection": "source"
      },
      {
        "namespace": "geoLocationManager",
        "method": "getCurrentLocation",
        "directCall": true,
        "permission": "ohos.permission.LOCATION",
        "profilingCategory": "location",
        "dataDirection": "source"
      }
    ]
  }
]
```

**字段说明：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `systemPackage` | string | 是 | ArkTS 包名，如 `@kit.BasicServicesKit` |
| `namespace` | string | 是 | API 命名空间，如 `deviceInfo`、`geoLocationManager` |
| `method` | string | 是 | 方法名，如 `productModel`、`getCurrentLocation` |
| `directCall` | boolean | 否 | `true`=精确匹配；`false`=后缀匹配；`null`=常量字段 |
| `permission` | string | 否 | 所需权限，如 `ohos.permission.LOCATION` |
| `profilingCategory` | string | 否 | 分析类别，如 `location`、`device_identity.hardware` |
| `dataDirection` | string | 否 | `source`/`sink`/`both`/`excluded` |

**directCall 三种取值的行为差异：**

| 值 | 含义 | 匹配例子 |
|----|------|----------|
| `true` | 直接调用 | `geoLocationManager.getCurrentLocation()` |
| `false` | 间接调用（后缀匹配） | `foo.geoLocationManager.getCurrentLocation()` |
| `null` | 常量字段 | `wifiManager.SCAN_RESULTS` |

### native_privacy_apis.json（Native 规则）

**文件位置：** `config/native_privacy_apis.json`

**结构：**

```json
{
  "schemaVersion": "1.0",
  "ruleType": "native_privacy_apis",
  "nativeApis": [
    {
      "symbol": "OH_GetDeviceType",
      "prototype": "const char *OH_GetDeviceType(void)",
      "category": "device_info",
      "profilingCategory": "device_identity.hardware",
      "apiPackage": "OpenHarmony.Native.DeviceInfo",
      "matchModes": ["import_symbol", "string_reference"]
    }
  ]
}
```

**字段说明：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `symbol` | string | 是 | C 函数名，如 `OH_GetDeviceType` |
| `prototype` | string | 否 | 函数签名 |
| `category` | string | 否 | 分类，如 `device_info`、`location` |
| `profilingCategory` | string | 否 | 分析类别 |
| `apiPackage` | string | 否 | 包名，如 `OpenHarmony.Native.DeviceInfo` |
| `matchModes` | array | 否 | `["import_symbol"]` 和/或 `["string_reference"]` |

### profile_combinations.json（多源联合规则）

**文件位置：** `config/profile_combinations.json`

**结构：**

```json
[
  {
    "ruleId": "DEVICE_LOCATION_WIFI",
    "ruleName": "设备+位置+WiFi联合",
    "matchScope": "same_method",
    "riskLevel": "high",
    "requiredApis": [
      {"category": "device_identity.hardware"},
      {"category": "location"},
      {"category": "network.wifi"}
    ]
  }
]
```

**matchScope 取值：**

| 值 | 含义 | 置信度 |
|----|------|--------|
| `same_method` | 所有 API 必须在同一函数内 | high |
| `lca` | 所有 API 必须在同一调用祖先函数下 | high |
| `same_file` | 所有 API 必须在同一文件中 | medium |

**requiredApis 中的匹配字段：**

- `api`：完整 API 名，如 `deviceInfo.productModel`
- `category`：分析类别，支持通配符 `device_identity.*`
- `namespace`：命名空间
- `method`：方法名

---

## 各模块详解

### PreciseSensitiveApiScanner — ArkTS 字节码分析核心

**职责：** 解析 `.abc` 文件，检测隐私 ArkTS API 调用。

**关键流程：**

```
1. collectAbcFiles()     → 递归收集所有 .abc 文件
2. parseAbcWithV1()      → Stage.createHiFile() 解析字节码
3. scanHiFile()          → 对每个 ABC：
   ├─ getAllStmtApiNameMap()  → 获取 API 调用映射
   ├─ getAllStmtFieldNameMap() → 获取字段访问映射
   ├─ matchDirectCall()        → directRules 匹配
   ├─ matchIndirectCall()      → indirectRules 匹配
   ├─ matchPrivacyConstant()   → constantRules 匹配
   ├─ isReachableFromEntry()   → CFG 可达性过滤
   └─ deduplicate()            → 去重
4. buildCallChainsForFile() → 调用链 + 数据流分析
```

**去重策略：** 按 `(file + function + stmtIndex + category + sourceKind)` 合并重复命中。

**SSA phi 节点过滤：** 跳过 `vN = vN.<method>` 格式的 SSA 伪赋值语句，这是编译器优化生成的中间代码，不是真正的 API 调用。

**@import 降级：** 来自第三方 SDK（API 名称前缀为 `@import`）的命中，置信度降至 `low`。

---

### CallGraphExplorer — 调用链构建

**职责：** 从敏感 API 所在函数反向追溯到应用入口函数。

**输入：** `CallGraph` + `Set<Stmt>`（含敏感 API 的语句）

**输出：** `List<CallChain>`（每条链包含 root → ... → sink 的函数列表）

**算法核心：**

```java
// 对每个含敏感 API 的函数 sinkFunc：
traceBackwards(CallGraph cg, HiFunction sinkFunc) {
    Set<HiFunction> callers = cg.getCallersByCallee(sinkFunc);

    if (callers == null || callers.isEmpty()) {
        // 递归终点：没有更多调用者，这就是入口函数
        saveChain(path);
        return;
    }

    for (HiFunction caller : callers) {
        // 递归向上追溯
        traceBackwards(cg, caller);
    }
}
```

**调用类型（callType）的判断规则：**

| caller 函数名模式 | callee 函数名模式 | callType |
|-------------------|-------------------|----------|
| `.build()` / `aboutToAppear()` | `onClick` / `handler` / `callback` | `lifecycle_trigger` |
| `onClick` / `ontouch` / `onsubmit` | 任意 | `event_handler_call` |
| 含 `callback` / `%resolve` / `%reject` | 任意 | `async_callback_call` |
| `onInit` / `onCreate` / `onReady` | 任意 | `lifecycle_init` |
| 其他 | 其他 | `direct` |

**入口函数类型判断：**

| 函数名模式 | type |
|-----------|------|
| `.build()` / `aboutToAppear()` / `onPageShow()` 等 | `component_lifecycle` |
| `onAbilityCreate()` / `onWindowStageCreate()` 等 | `ability_lifecycle` |
| `XXXComponent` / `XXXPage` / `XXXView` 等 | `ui_component` |
| `onClick()` / `onChange()` 等 | `event_handler` |
| `callback` / `then()` 等 | `async_callback` |
| `func_main_0` / `func_` 等 | `entry_point` |

---

### DataFlowExplorer — 数据流分析（IFDS）

**职责：** 追踪隐私数据从 source API（数据源）到 sink API（数据汇）的传播路径。

**核心概念：**

```
SOURCE（数据源）：读取隐私数据的 API
  例：geoLocationManager.getCurrentLocation() — 读取位置
      wifiManager.getScanInfoList() — 读取 WiFi 列表

SINK（数据汇）：输出/存储数据的 API
  例：http.request() — 网络上传
      fs.write() — 文件写入
      preferences.put() — 本地存储
```

**IFDS 工作方式：**

```
1. 收集所有 SOURCE 语句（隐私 API 命中）
2. 收集所有候选 SINK 语句（网络/存储/日志 API）
3. 对每个 SOURCE，单独运行 IFDS 污点分析
   → 若能从 SOURCE 追踪到某个 SINK → 标记为隐私数据泄漏
```

**为什么逐个 SOURCE 分析？**

华为工具的 `TaintAnalysis.solveAndGetResults()` 全局模式下，会把所有 SOURCE 的污染 sinks 混合在一起，不能区分"哪个 SOURCE 到达哪个 SINK"。所以 ArkPrism 采用逐个 SOURCE 分析。

**容错设计：** IFDS 分析若失败（工具内部错误），静默跳过，不影响主流程。

---

### MultiSourceCollaborationAnalyzer — 多源联合检测

**职责：** 检测"同一方法/祖先/文件内多种敏感数据被组合访问"的行为。

**三种检测粒度：**

```
same_method：所有 API 在同一个函数内
  ┌─────────────────────────────────┐
  │  void onButtonClick() {         │
  │    getDeviceModel()  ← 设备ID   │
  │    getLocation()     ← 位置     │
  │    getWifiList()     ← WiFi     │
  │  }                              │
  └─────────────────────────────────┘
  → 三个 API 在同一函数中触发规则

lca：所有 API 在同一调用祖先下
  ┌─────────────────────────────────┐
  │  void onInit() {                │
  │    loadDeviceProfile() ──┐      │
  │  }                        │     │
  │                            ↓     │
  │  void loadDeviceProfile() {     │
  │    getDeviceModel()  ←──┼──┐    │
  │  }                        │     │
  │                            ↓     │
  │  void loadLocation() {          │
  │    getLocation()      ←──┼──┘   │
  │  }                            │
  └─────────────────────────────────┘
  → onInit 是 LCA，三个 API 都在其调用树下

same_file：所有 API 在同一文件中
  → 置信度降为 medium（同一文件内可能不在同一个函数中）
```

**LCA 算法（基于 CallGraph）：**

```
1. 构建 CallGraph（CHA 算法，快速保守）
2. BFS 从所有入口函数向下，收集每个函数的深度
3. 对每个目标函数（含有敏感 API 的函数），反向 BFS 收集祖先链
4. 找深度最浅的共同祖先 → 即为 LCA
5. BFS 验证从 LCA 到每个目标函数的可达性
```

---

### SoVulnerabilityScanner — Native SO 分析

**职责：** 调用 angr 扫描 SO 文件中的隐私 C API。

**执行流程：**

```
Java 进程
  ├─ SoVulnerabilityScanner.scanSingleSoFile()
  │     ├─ 构建 wsl.exe 命令
  │     └─ ProcessBuilder 启动 WSL 进程
  │
WSL 进程
  └─ python pure_angr_scanner.py <so_path> <rule_path>
        ├─ angr.Project(so_path) — 加载 ELF
        ├─ analyze_import_symbols() — 导入表匹配
        ├─ analyze_string_references() — 字符串扫描
        └─ 输出 JSON 到 stdout
```

**跳过运行时库：** 以下 SO 文件默认跳过（避免框架库误报）：

```
libc++_shared.so    — C++ 标准库
libjsruntime.so     — JS 运行时
libark_jsruntime.so — Ark JS 运行时
libace_napi.z.so    — ACE NAPI 封装
libhilog.so         — 日志库
libnative_bridge.so — Native 桥接
```

**Python 脚本的 stdout 重定向：** 所有日志输出到 stderr，只有最终 JSON 结果输出到 stdout，避免污染 Java 的输入流。

---

### PrivacyCatalog — Source/Sink 目录

**职责：** 从 `privacy_apis.json` 加载 source 和 sink API 集合，供数据流分析使用。

**dataDirection 解析优先级：**

```
1. 规则中显式声明 dataDirection 字段 → 直接使用
2. 无 dataDirection → 从 profilingCategory 推断

推断规则：
  location / device_identity.* / media.* / user_data.* / user_behavior.*
    → source

  network.* / data_storage.* / app_analytics.*
    → sink

  device_identity.screen / battery / uptime / vibrator
    → excluded（无隐私风险）
```

---

## 常见问题

### Q: 分析时内存占用大怎么办？

**A:** ArkPrism 在每个 HAP 分析结束后会调用 `System.gc()` 释放内存。若仍不足，可将 `input/` 中的 HAP 数量减少，分批分析。

### Q:ArkTS 扫描出现 "V1 parser failed" 怎么办？

**A:** 华为分析工具对部分 ArkTS 方言支持有限。可以：
1. 确认 `.abc` 文件是从 ArkTSV1 编译器生成的
2. 检查日志中的具体错误信息
3. 该 ABC 会自动跳过，不影响其他文件

### Q:SO 扫描找不到 angr？

**A:** 确保：
1. angr 已安装在 WSL 中：`pip install angr`
2. 设置了环境变量：`set ARKPRISM_WSL_SCANNER=/mnt/d/Projects/ArkPrism/angr/pure_angr_scanner.py`

### Q: 多源联合检测没有输出？

**A:** 检查：
1. `config/profile_combinations.json` 是否存在且格式正确
2. 隐私 API 命中数量是否足够（需要至少 2 个不同类别的 API）
3. API 是否都在同一方法/文件中

### Q: 如何添加新的隐私 API 规则？

**A:** 编辑 `config/privacy_apis.json`，追加新的规则条目：

```json
{
  "systemPackage": "@kit.NewKit",
  "category": "new_category",
  "privacyApis": [
    {
      "namespace": "newManager",
      "method": "getNewData",
      "directCall": true,
      "permission": "ohos.permission.NEW_PERMISSION",
      "profilingCategory": "new.category",
      "dataDirection": "source"
    }
  ]
}
```

### Q: 置信度 low 是什么意思？

**A:** 置信度 low 表示该命中可能是误报，主要原因：

| 原因 | 触发条件 |
|------|----------|
| 不可达代码 | CFG 分析发现语句不在任何可达路径上 |
| SSA phi 节点 | 语句是编译器生成的伪赋值 |
| @import SDK | 来自第三方 SDK，非应用自有代码 |
| 字符串引用 | SO 中只有字符串引用，无导入表证据 |

### Q: 报 `Could not initialize class com.huawei.hianalyzer.utils.FileUtil`

**A:** 在 `pom.xml` 中加入 slf4j 依赖：

```xml
<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-api</artifactId>
    <version>1.7.36</version>
</dependency>
<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-simple</artifactId>
    <version>1.7.36</version>
</dependency>
```

---

## 参考资料

- [华为 ArkAnalyzer 官方文档](https://developer.huawei.com/consumer/cn/doc/harmonyos-guides/)
- [IFDS 论文：Interprocedural Data Flow Analysis](https://en.wikipedia.org/wiki/IFDS_Framework)
- [Andersen PTA：指向分析算法](https://en.wikipedia.org/wiki/Pointer_analysis)
- [angr 符号执行框架](https://angr.io/)