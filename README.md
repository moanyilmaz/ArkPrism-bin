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

#### 源码位置

`src/main/java/com/huawei/hisec/PreciseSensitiveApiScanner.java`

#### 核心类结构

```java
public class PreciseSensitiveApiScanner {

    // 内部数据模型
    public static class SensitiveApiHit { ... }   // 单条命中
    public static class ArkTsScanResult { ... }  // 扫描结果

    // 公开入口
    public ArkTsScanResult scanDirectory(File targetDirectory, File ruleJsonFile)

    // 私有方法
    private HiFile parseAbcWithV1(File abcFile, List<String> warnings)
    private List<SensitiveApiHit> scanHiFile(HiFile hiFile, String fileName, ...)
    private void buildCallChainsForFile(HiFile hiFile, File abcFile, ...)
}
```

#### 入口方法：scanDirectory()

```java
// PreciseSensitiveApiScanner.java 第 136-301 行
public ArkTsScanResult scanDirectory(File targetDirectory, File ruleJsonFile) {
    // 1. 加载隐私 API 规则
    List<PrivacyPackageInfo> packageInfos = loadPrivacyApis(ruleJsonFile.getAbsolutePath());
    List<PrivacyApiRuleWithPkg> allRules = flattenRules(packageInfos);

    // 2. 按 directCall 分类规则
    List<PrivacyApiRuleWithPkg> directRules = allRules.stream()
        .filter(r -> Boolean.TRUE.equals(r.rule.directCall))      // directCall = true
        .filter(r -> !"excluded".equalsIgnoreCase(r.rule.dataDirection))
        .collect(Collectors.toList());

    List<PrivacyApiRuleWithPkg> indirectRules = allRules.stream()
        .filter(r -> Boolean.FALSE.equals(r.rule.directCall))     // directCall = false
        .filter(r -> !"excluded".equalsIgnoreCase(r.rule.dataDirection))
        .collect(Collectors.toList());

    List<PrivacyApiRuleWithPkg> constantRules = allRules.stream()
        .filter(r -> r.rule.directCall == null)                    // directCall = null
        .filter(r -> !"excluded".equalsIgnoreCase(r.rule.dataDirection))
        .collect(Collectors.toList());

    // 3. 遍历每个 .abc 文件
    for (File abcFile : abcFiles) {
        HiFile hiFile = parseAbcWithV1(abcFile, result.warnings);
        List<SensitiveApiHit> hits = scanHiFile(hiFile, abcFile.getName(),
                directRules, indirectRules, constantRules);

        // 4. 转换为 ApiUsage + 构建调用链
        List<UnifiedPrivacyReport.ApiUsage> dedupedUsages = ...
        Map<Stmt, Integer> sourceStmtToApiUsageIndex = ...
        buildCallChainsForFile(hiFile, abcFile, sinkStmts, ...);
    }
}
```

**关键设计点：为什么按 directCall 分类？**

因为三种规则的匹配逻辑完全不同，放在三个独立的 `match*()` 方法中处理，避免 `if-else` 嵌套爆炸。

#### 字节码解析：parseAbcWithV1()

```java
// PreciseSensitiveApiScanner.java 第 311-327 行
private HiFile parseAbcWithV1(File abcFile, List<String> warnings) {
    try {
        // 华为分析工具 API：将 .abc 文件解析为 HiFile 对象
        HiFile hiFile = Stage.createHiFile(abcFile.getAbsolutePath(), SourceLang.ARKTSV1);
        if (hiFile != null) {
            int funcCount = hiFile.getHiFunctions() == null ? 0 : hiFile.getHiFunctions().size();
            Logger.log("    [+] ARKTSV1: success, functions=" + funcCount);
            return hiFile;
        } else {
            Logger.log("    [-] ARKTSV1: returned null");
            return null;
        }
    } catch (Throwable t) {
        Logger.log("    [-] ARKTSV1: " + t.getMessage());
        return null;
    }
}
```

**返回的 HiFile 结构：**

```
HiFile
├── List<HiFunction> getHiFunctions()
│     ├── HiFunction #1
│     │     └── Body
│     │           └── List<Stmt> (语句序列)
│     └── HiFunction #2
│           └── Body
│                 └── List<Stmt>
```

#### 核心扫描：scanHiFile()

```java
// PreciseSensitiveApiScanner.java 第 561-652 行
private List<SensitiveApiHit> scanHiFile(HiFile hiFile, String fileName,
        List<PrivacyApiRuleWithPkg> directRules,
        List<PrivacyApiRuleWithPkg> indirectRules,
        List<PrivacyApiRuleWithPkg> constantRules) {

    List<SensitiveApiHit> results = new ArrayList<>();

    // 华为分析工具提供两个 API 映射：
    // ① getAllStmtApiNameMap() — 语句 → API 调用名称
    //    例：VirtualCall: %0.<geoLocationManager.getCurrentLocation>
    //        → "geoLocationManager.getCurrentLocation"
    Map<Stmt, String> stmtApiMap = safeGetAllStmtApiNameMap(hiFile);

    // ② getAllStmtFieldNameMap() — 语句 → 字段访问名称
    //    例：FieldLoad: %0.deviceInfo.productModel
    //        → "deviceInfo.productModel"
    Map<Stmt, String> stmtFieldMap = safeGetAllStmtFieldNameMap(hiFile);

    // ===== 遍历 API 调用语句 =====
    for (Map.Entry<Stmt, String> entry : stmtApiMap.entrySet()) {
        Stmt stmt = entry.getKey();
        String fullApiName = normalizeFullName(entry.getValue());
        ResolvedNameInfo info = parseResolvedName(fullApiName);

        // 过滤：跳过 @unknown / @internal / @bundle 前缀
        if (!isAcceptedResolvedName(info)) continue;

        // 三种匹配策略
        SensitiveApiHit directHit = matchDirectCall(stmt, info, ... directRules ...);
        if (directHit != null) { results.add(directHit); continue; }

        SensitiveApiHit indirectHit = matchIndirectCall(stmt, info, ... indirectRules ...);
        if (indirectHit != null) { results.add(indirectHit); }
    }

    // ===== 遍历字段访问语句 =====
    for (Map.Entry<Stmt, String> entry : stmtFieldMap.entrySet()) {
        // 先匹配常量字段
        SensitiveApiHit fieldHit = matchPrivacyConstant(stmt, info, ... constantRules ...);
        if (fieldHit != null) { results.add(fieldHit); continue; }

        // 再匹配链式调用
        SensitiveApiHit directChain = matchDirectCall(stmt, info, ... directRules ...);
        if (directChain != null) { results.add(directChain); continue; }

        SensitiveApiHit indirectChain = matchIndirectCall(stmt, info, ... indirectRules ...);
        if (indirectChain != null) { results.add(indirectChain); }
    }

    return deduplicate(results);
}
```

#### 名称解析：parseResolvedName()

ArkTS 编译器会将 API 名称编码为特定格式，解析器负责将其拆解：

```java
// PreciseSensitiveApiScanner.java 第 913-976 行
private ResolvedNameInfo parseResolvedName(String fullName) {
    ResolvedNameInfo info = new ResolvedNameInfo();
    info.original = fullName;

    // 前缀解析：@system:@ohos:geoLocationManager.getCurrentLocation
    //           @import:lodash.debounce
    //           @bundle:&@app/ets/...
    if (fullName.startsWith("@system:")) {
        info.sourcePrefix = "@system";      // 系统 API
        s = fullName.substring(8);
    } else if (fullName.startsWith("@import:")) {
        info.sourcePrefix = "@import";      // 第三方 SDK
        s = fullName.substring(8);
    } else if (fullName.startsWith("@unknown:")) {
        info.sourcePrefix = "@unknown";     // 无法解析
        ...
    }

    // 路径解析：从 "namespace:method" 中提取 namespace
    int colon = s.indexOf(':');
    info.rootQualifier = s.substring(0, colon).trim();  // "geoLocationManager"
    String pathPart = s.substring(colon + 1).trim();    // "getCurrentLocation"

    // 分词：pathPart = "geoLocationManager.getCurrentLocation"
    //       → pathTokens = ["geoLocationManager", "getCurrentLocation"]
    for (String p : pathPart.split("\\.")) {
        info.pathTokens.add(p.trim());
    }

    info.lastToken = pathTokens.get(pathTokens.size() - 1);  // "getCurrentLocation"
    info.prefixTokens = pathTokens.subList(0, pathTokens.size() - 1);  // ["geoLocationManager"]

    info.valid = true;
    return info;
}
```

**为什么要分词？**

因为有些 API 是链式调用 `foo.bar.geoLocationManager.getCurrentLocation`，需要通过 pathTokens 判断 `geoLocationManager` 是否紧邻 `method`。

#### 三种匹配策略

**1. matchDirectCall() — 直接调用（精确匹配 namespace）**

```java
// PreciseSensitiveApiScanner.java 第 654-682 行
private SensitiveApiHit matchDirectCall(Stmt stmt, ResolvedNameInfo info,
        String fileName, String functionName,
        List<PrivacyApiRuleWithPkg> directRules, String layer, String sourceKind) {

    // 匹配条件：
    // ① 方法名相等（info.lastToken == rule.method）
    // ② namespace 必须紧邻 method（namespaceMustBePredecessor）
    for (PrivacyApiRuleWithPkg item : directRules) {
        if (!Objects.equals(item.rule.method, info.lastToken))
            continue;
        if (!namespaceMustBePredecessor(info.pathTokens, item.rule.namespace))
            continue;

        // 命中！创建 hit
        SensitiveApiHit hit = createBaseHit(stmt, info, fileName, functionName, item, layer, sourceKind);

        // 判断是否有赋值语句（影响 category 描述）
        String stmtText = safe(stmt);
        boolean assignmentLike = stmtText != null && stmtText.contains("=");
        hit.category = assignmentLike ? "direct invoke stmt after assignment" : "direct invoke stmt";
        return hit;
    }
    return null;
}
```

**为什么需要 namespaceMustBePredecessor？**

考虑一个反例：规则是 `namespace=deviceInfo`，但实际调用是 `foo.deviceInfo.bar.productModel`。如果不检查 namespace 是否紧邻 method，会错误匹配到这个链式调用的中间段。

```java
// namespaceMustBePredecessor 实现：
// PreciseSensitiveApiScanner.java 第 1088-1098 行
private boolean namespaceMustBePredecessor(List<String> pathTokens, String namespace) {
    // pathTokens = ["foo", "deviceInfo", "bar", "productModel"]
    // namespace = "deviceInfo"
    // 要求：namespace 必须位于 pathTokens[size-2]（即紧邻 method）
    // 这里 deviceInfo 在 index=1，不是 size-2=2 → 不匹配

    String actualNs = pathTokens.get(pathTokens.size() - 2);
    return namespace.equals(actualNs);
}
```

**2. matchIndirectCall() — 间接调用（后缀匹配）**

```java
// PreciseSensitiveApiScanner.java 第 684-713 行
private SensitiveApiHit matchIndirectCall(Stmt stmt, ResolvedNameInfo info, ...) {

    // 匹配条件：路径末尾是规则中的 method
    // 例如：someObj.geoLocationManager.getCurrentLocation
    //       → pathTokens = ["someObj", "geoLocationManager", "getCurrentLocation"]
    //       → 规则 method = "getCurrentLocation"
    //       → endsWithDotted 匹配成功

    String joinedPath = String.join(".", info.pathTokens);

    for (PrivacyApiRuleWithPkg item : indirectRules) {
        if (!endsWithDotted(joinedPath, item.rule.method)) continue;
        if (!namespaceMustBePredecessor(info.pathTokens, item.rule.namespace)) continue;

        SensitiveApiHit hit = createBaseHit(stmt, info, ...);
        hit.category = "indirect invoke";
        return hit;
    }
    return null;
}
```

**3. matchPrivacyConstant() — 常量字段**

```java
// PreciseSensitiveApiScanner.java 第 715-740 行
private SensitiveApiHit matchPrivacyConstant(Stmt stmt, ResolvedNameInfo info, ...) {

    // 匹配条件：最后一级字段名 == 规则 method
    // 例如：wifiManager.SCAN_RESULTS → 匹配 wifiManager.SCAN_RESULTS
    for (PrivacyApiRuleWithPkg item : constantRules) {
        if (!Objects.equals(item.rule.method, info.lastToken)) continue;
        if (!namespaceMustBePredecessor(info.pathTokens, item.rule.namespace)) continue;

        SensitiveApiHit hit = createBaseHit(stmt, info, ...);
        hit.category = "privacy constants";
        return hit;
    }
    return null;
}
```

#### 创建命中：createBaseHit()

```java
// PreciseSensitiveApiScanner.java 第 742-785 行
private SensitiveApiHit createBaseHit(Stmt stmt, ResolvedNameInfo info,
        String fileName, String functionName,
        PrivacyApiRuleWithPkg item, String layer, String sourceKind) {

    SensitiveApiHit hit = new SensitiveApiHit();
    hit.layer = layer;            // BODY_HIT 或 CHAIN_EVIDENCE
    hit.sourceKind = sourceKind;  // API_MAP 或 FIELD_MAP
    hit.systemPackage = item.systemPackage;
    hit.namespace = item.rule.namespace;
    hit.method = item.rule.method;
    hit.permission = item.rule.permission;
    hit.profilingCategory = item.rule.profilingCategory;
    hit.dataDirection = item.rule.dataDirection;
    hit.matchedFullName = info.original;
    hit.stmtClass = stmt.getClass().getName();
    hit.stmtText = safe(stmt);    // 原始 IR 文本，如 "VirtualCall: %0.<deviceInfo.productModel>"
    hit.file = fileName;
    hit.function = functionName;
    hit.stmtIndex = safeStmtIndex(stmt);
    hit.stmtObj = stmt;           // 保留 Stmt 对象引用，供后续 CFG 分析用

    // ===== 过滤 1：CFG 可达性 =====
    if (!isReachableFromEntry(stmt)) {
        hit.confidence = "low";
        hit.category = "(unreachable) " + hit.category;
    }

    // ===== 过滤 2：Def-Use 分析 =====
    // 如果语句定义了一个值但之后没有任何地方使用它，可能是死代码
    if (!DataFlowExplorer.isValueUsed(stmt)) {
        hit.confidence = "low";
        hit.category = "(unused_def) " + hit.category;
    }

    return hit;
}
```

**layer = BODY_HIT vs CHAIN_EVIDENCE 的区别：**

- `BODY_HIT`：直接命中（调用语句在函数体中）
- `CHAIN_EVIDENCE`：间接命中（通过字段访问链关联到 API）

#### CFG 可达性检查：isReachableFromEntry()

```java
// PreciseSensitiveApiScanner.java 第 1111-1177 行
private static boolean isReachableFromEntry(Stmt targetStmt) {
    HiFunction func = targetStmt.getHiFunction();

    // 快速路径：如果是入口语句，直接可达
    Stmt entryStmt = body.getEntryStmt();
    if (entryStmt == targetStmt) return true;

    // 方法 1：BlockGraph 块级可达性（更快）
    BlockGraph blockGraph = BlockGraph.createOrGetGraph(func);
    BasicBlock containingBlock = findContainingBlock(blockGraph, targetStmt);
    if (containingBlock == entryBlock) return true;  // 在入口块中

    DominantTree domTree = new DominantTree(blockGraph);
    if (isBlockReachableFromEntry(blockGraph, domTree, containingBlock)) {
        return true;  // 块可达
    }
    return false;  // 块不可达 → 死代码

    // 方法 2：StmtGraph 语句级 BFS（精确但慢）
    StmtGraph stmtGraph = Stage.createOrGetStmtGraph(func);
    return isStmtReachableBFS(stmtGraph, entryStmt, targetStmt);
}
```

**为什么用两种方法？**

BlockGraph 只检查语句所在的块是否可达（粗粒度），StmtGraph 做语句级 BFS（细粒度但更慢。优先用 BlockGraph，BlockGraph 失败才回退到 StmtGraph。

#### SSA phi 节点过滤

编译器 SSA 优化会生成伪赋值语句，这些不是真正的 API 调用：

```java
// PreciseSensitiveApiScanner.java 第 1046-1082 行
private boolean isSsaPhiNode(String stmtText) {
    // 模式：vN = vN.<method>
    //       v10 = v10.<write>     ← SSA phi，忽略
    //       v10 = v8.<write>      ← 真实调用，保留

    int eq = stmtText.indexOf('=');
    String lhs = stmtText.substring(0, eq).trim();   // "v10"
    String rhs = stmtText.substring(eq + 1).trim();  // "VirtualCall: v10.<write>"

    if (!lhs.matches("v\\d+")) return false;  // LHS 不是 SSA 变量

    if (rhs.startsWith("VirtualCall: ")) {
        String inside = rhs.substring("VirtualCall: ".length()).trim();
        // 检查 RHS 的接收者是否和 LHS 相同
        if (inside.startsWith(lhs + ".")) return true;  // v10 = v10.<method>
    }
    return false;
}
```

#### 调用链构建：buildCallChainsForFile()

```java
// PreciseSensitiveApiScanner.java 第 333-420 行
private void buildCallChainsForFile(HiFile hiFile, File abcFile,
        Set<Stmt> sinkStmts, Map<Stmt, Integer> sourceStmtToApiUsageIndex, ...) {

    // 1. 构建 Andersen PTA 调用图
    CallGraph cg = Stage.createCallGraph(hiFile, CallGraph.CGBuildMethod.ANDERSEN, true);

    // 2. 提取调用链（逆向 DFS）
    List<CallGraphExplorer.CallChain> chains =
        CallGraphExplorer.extractPrivacyCallChains(hiFile, cg, sinkStmts);

    // 3. IFDS 数据流分析
    Map<Stmt, List<CallStmt>> dataFlowResults =
        DataFlowExplorer.findDataSinks(hiFile, cg, sinkStmts, ruleJsonPath);

    // 4. 为每个 sinkStmt 生成 CallChainReport
    for (Stmt sourceStmt : sinkStmts) {
        Integer apiUsageIndex = sourceStmtToApiUsageIndex.get(sourceStmt);
        List<CallGraphExplorer.CallChain> relatedChains = chains.stream()
            .filter(c -> c.sinkNode.equals(sourceFunc))
            .collect(Collectors.toList());

        for (CallGraphExplorer.CallChain chain : relatedChains) {
            UnifiedPrivacyReport.CallChainReport reportChain = convertCallChain(...);
            outputChains.add(reportChain);
        }
    }
}
```

---

### CallGraphExplorer — 调用链构建

**职责：** 从敏感 API 所在函数反向追溯到应用入口函数，构建完整调用路径。

#### 源码位置

`src/main/java/com/huawei/hisec/CallGraphExplorer.java`

#### 核心数据结构

```java
public static class CallChain {
    public HiFunction rootNode;  // 入口函数（如 onClick）
    public HiFunction sinkNode;  // 包含敏感 API 的函数
    public List<HiFunction> path;  // 完整路径：root → ... → sink
}
```

#### 公开入口

```java
// CallGraphExplorer.java 第 34 行
public static List<CallChain> extractPrivacyCallChains(
        HiFile hiFile, CallGraph cg, Set<Stmt> sinkStmts) {

    // 1. 从 sinkStmts 提取所有包含敏感 API 的函数
    Set<HiFunction> sinkFunctions = new HashSet<>();
    for (Stmt stmt : sinkStmts) {
        HiFunction func = safeGetHiFunction(stmt);
        sinkFunctions.add(func);
    }

    // 2. 对每个 sinkFunc 执行 DFS 反向追溯
    for (HiFunction sinkFunc : sinkFunctions) {
        List<HiFunction> currentPath = new ArrayList<>();
        currentPath.add(sinkFunc);
        traceBackwards(cg, sinkFunc, currentPath, allChains, visited);
    }
    return allChains;
}
```

#### 核心追溯算法：traceBackwards()

```java
// CallGraphExplorer.java 第 69-99 行
private static void traceBackwards(CallGraph cg, HiFunction current,
        List<HiFunction> currentPath, List<CallChain> allChains,
        Set<HiFunction> visited) {

    // 获取调用当前函数的所有函数（反向边）
    Set<HiFunction> callers = cg.getCallersByCallee(current);

    // 递归终点 1：没有调用者 → 到达入口函数
    if (callers == null || callers.isEmpty()) {
        saveChain(currentPath, current, allChains);
        return;
    }

    boolean isAllVisited = true;
    for (HiFunction caller : callers) {
        if (!visited.contains(caller)) {
            isAllVisited = false;
            visited.add(caller);
            currentPath.add(caller);
            traceBackwards(cg, caller, currentPath, allChains, visited);
            currentPath.remove(currentPath.size() - 1);  // 回溯
            visited.remove(caller);
        }
    }

    // 递归终点 2：所有调用者都被访问过（循环调用）
    if (isAllVisited && !callers.isEmpty()) {
        saveChain(currentPath, current, allChains);
    }
}
```

**Andersen PTA 生成的调用图特点：**

Andersen 是上下文不敏感的指针分析，对于多态调用会返回所有可能的实现。例如：

```java
class A { void foo() }
class B extends A { void foo() }

A obj = factory();  // 可能是 A 也可能是 B
obj.foo();          // Andersen 会返回 {A.foo, B.foo}
```

所以 `getCallersByCallee(sinkFunc)` 可能返回多个调用者。

#### 保存链：saveChain()

```java
// CallGraphExplorer.java 第 104-117 行
private static void saveChain(List<HiFunction> currentPath,
        HiFunction currentRoot, List<CallChain> allChains) {

    CallChain chain = new CallChain();
    // DFS 是从 sink 向入口追溯的，所以 currentPath[0] 是 sink
    chain.sinkNode = currentPath.get(0);
    chain.rootNode = currentRoot;  // DFS 尽头（最远的调用者）

    // 反转路径：从入口到 sink
    List<HiFunction> reversePath = new ArrayList<>(currentPath);
    Collections.reverse(reversePath);
    chain.path = reversePath;

    allChains.add(chain);
}
```

**路径示例：**

```
DFS 追溯过程（从 sink 向入口）：
  1. start: [deviceInfo.productModel]      ← sink
  2. after 1 step: [getDeviceInfo, deviceInfo.productModel]
  3. after 2 steps: [aboutToAppear, getDeviceInfo, deviceInfo.productModel]
  4. aboutToAppear 没有调用者 → 递归终点

saveChain 时 reverse：
  [aboutToAppear, getDeviceInfo, deviceInfo.productModel]
  ↑ 入口                                          ↑ sink
```

---

### DataFlowExplorer — 数据流分析（IFDS）

**职责：** 基于 IFDS（Interprocedural Data Flow Analysis）追踪隐私数据从 source API 到 sink API 的传播路径。

#### 源码位置

`src/main/java/com/huawei/hisec/DataFlowExplorer.java`

#### Source 和 Sink 定义

```java
// DataFlowExplorer.java 第 69-127 行

// SOURCE：读取隐私数据的 API 关键字
private static final Set<String> SOURCE_KEYWORD_PATTERNS = new HashSet<>(Arrays.asList(
    "geoLocationManager.getCurrentLocation",
    "geoLocationManager.getLastLocation",
    "deviceInfo.brand",
    "deviceInfo.productModel",
    "deviceInfo.deviceType",
    "wifiManager.getDeviceMacAddress",
    "wifiManager.getScanInfoList",
    "identifier.oaid",
    "contact.selectContacts",
    // ... 共 50+ 条
));

// SINK：网络上传
private static final Set<String> NETWORK_SINKS = new HashSet<>(Arrays.asList(
    "@system:@ohos:net.http.request",
    "@system:@ohos:net.http.createHttp",
    "@system:@ohos:net.socket.constructTCPSocketInstance",
    "@system:@ohos:request.uploadFile",
    "@system:@ohos:web.webview.loadUrl",
    // ...
));

// SINK：本地存储
private static final Set<String> STORAGE_SINKS = new HashSet<>(Arrays.asList(
    "@system:@ohos:file.fs.open",
    "@system:@ohos:file.fs.write",
    "@system:@ohos:data.preferences.put",
    "@system:@ohos:data.preferences.flushSync",
    "@system:@ohos:data.distributedKVStore.getKVStore",
    // ...
));

// SINK：日志
private static final Set<String> LOGGING_SINKS = new HashSet<>(Arrays.asList(
    "console.log",
    "console.info",
    "console.warn",
    "@system:@ohos:hiAppEvent.write"
));
```

#### 公开入口：findDataSinks()

```java
// DataFlowExplorer.java 第 234-273 行
public static Map<Stmt, List<CallStmt>> findDataSinks(
        HiFile hiFile, CallGraph cg, Set<Stmt> sourceStmts, String jsonPath) {

    Map<Stmt, List<CallStmt>> sourceToSinksMap = new LinkedHashMap<>();

    // 1. 加载 source/sink 目录（从 privacy_apis.json）
    ensureCatalog(jsonPath);

    // 2. 收集有效的 SOURCE 语句（必须是 CallStmt + 有函数体 + 是已知 SOURCE）
    Set<CallStmt> ifdsSources = collectValidSources(hiFile, sourceStmts);

    // 3. 收集所有候选 SINK 语句
    Set<CallStmt> ifdsSinks = collectCandidateSinks(hiFile);

    // 4. 构建 ICFG（过程间控制流图）
    ICFG icfg = Stage.createICFG(hiFile, cg);

    // 5. 对每个 SOURCE 单独运行 IFDS（避免全局模式的结果混淆）
    if (RUN_PER_SOURCE) {
        return runIfdsPerSource(hiFile, cg, ifdsSources, ifdsSinks);
    } else {
        return runIfdsGlobal(hiFile, cg, ifdsSources, ifdsSinks);
    }
}
```

#### 逐个 SOURCE 分析：runIfdsPerSource()

```java
// DataFlowExplorer.java 第 329-392 行
private static Map<Stmt, List<CallStmt>> runIfdsPerSource(...) {
    Map<Stmt, List<CallStmt>> result = new LinkedHashMap<>();

    ICFG icfg = Stage.createICFG(hiFile, cg);

    for (CallStmt source : ifdsSources) {
        Set<CallStmt> singleSource = new HashSet<>();
        singleSource.add(source);

        try {
            // 创建针对这一个 SOURCE 的污点分析任务
            TaintAnalysis taintAnalysis = TaintAnalysis.createTaintAnalysisByStmt(
                    singleSource,   // 只有一个 SOURCE
                    ifdsSinks       // 所有候选 SINK
            );

            // 运行 IFDS，返回被污染的 SINK 集合
            Set<CallStmt> hitSinks = taintAnalysis.solveAndGetResults(icfg);

            if (hitSinks != null && !hitSinks.isEmpty()) {
                result.put(source, new ArrayList<>(hitSinks));
            }
        } catch (Throwable t) {
            // IFDS 失败 → 静默跳过
        }
    }
    return result;
}
```

**为什么不用全局 IFDS？**

华为工具的 `TaintAnalysis.solveAndGetResults(icfg)` 返回的是**所有 SOURCE 共同的污染 SINK 集合**，不区分"哪个 SOURCE 到达了哪个 SINK"。例如：

```
SOURCE_1 = geoLocationManager.getCurrentLocation
SOURCE_2 = deviceInfo.productModel
SINK_A = console.log
SINK_B = http.request

全局模式结果：{SINK_A, SINK_B}
→ 无法知道 SOURCE_1 到达了哪些 SINK

逐个 SOURCE 模式：
SOURCE_1 → {SINK_B}（位置信息只上传）
SOURCE_2 → {SINK_A}（设备信息只打日志）
→ 每个 SOURCE 的数据流向清晰
```

#### SOURCE 有效性检查：collectValidSources()

```java
// DataFlowExplorer.java 第 401-428 行
private static Set<CallStmt> collectValidSources(HiFile hiFile, Set<Stmt> sourceStmts) {
    Set<CallStmt> result = new LinkedLinkedHashSet<>();

    for (Stmt stmt : sourceStmts) {
        if (!(stmt instanceof CallStmt)) continue;

        CallStmt callStmt = (CallStmt) stmt;
        HiFunction sourceFunc = getHiFunctionSafe(callStmt);
        if (sourceFunc == null || !hasValidBody(sourceFunc)) continue;

        String apiName = safeGetFullApiName(hiFile, callStmt);

        // 两个条件同时满足才是有效 SOURCE：
        // ① 是已知的 SOURCE API（在 privacy_apis.json 中标记为 source）
        // ② 是 CallStmt（函数调用）
        boolean isSource = catalog.isSourceApi(hiFile, callStmt);
        if (!isSource) continue;

        result.add(callStmt);
    }
    return result;
}
```

#### SINK 类型推断：inferSinkType()

```java
// DataFlowExplorer.java 第 889-907 行
private static String inferSinkType(String sinkApi) {
    if (sinkApi.contains("console.log") || sinkApi.contains("console.info")) {
        return "log";
    }
    if (sinkApi.contains("http") || sinkApi.contains("request") || sinkApi.contains("upload")) {
        return "network";
    }
    if (sinkApi.contains("preferences") || sinkApi.contains("put") || sinkApi.contains("kvstore")) {
        return "storage";
    }
    return "unknown";
}
```

---

### MultiSourceCollaborationAnalyzer — 多源联合检测

**职责：** 检测"同一方法/祖先/文件内多种敏感数据被组合访问"的隐蔽行为。

#### 源码位置

`src/main/java/com/huawei/hisec\MultiSourceCollaborationAnalyzer.java`

#### 公开入口

```java
// MultiSourceCollaborationAnalyzer.java 第 62-87 行
public static List<UnifiedPrivacyReport.MultiSourceCollaboration> analyze(
        UnifiedPrivacyReport report, File ruleFile, HiFile hiFile) {

    // 加载组合规则
    List<ProfileCombinationRule> rules = loadRules(ruleFile);

    // 构建调用图（用于 LCA 分析）
    CallGraph callGraph = buildCallGraph(hiFile);

    // 三种检测粒度，结果合并
    List<UnifiedPrivacyReport.MultiSourceCollaboration> results = new ArrayList<>();
    results.addAll(analyzeSameMethodByRules(report, rules));        // 同一方法
    results.addAll(analyzeLcaByRules(report, rules, callGraph));    // 同一祖先
    results.addAll(analyzeSameFileByRules(report, rules));          // 同一文件
    return results;
}
```

#### same_method 检测：analyzeSameMethodByRules()

```java
// MultiSourceCollaborationAnalyzer.java 第 111-155 行
private static List<UnifiedPrivacyReport.MultiSourceCollaboration>
analyzeSameMethodByRules(UnifiedPrivacyReport report, List<ProfileCombinationRule> rules) {

    // 1. 按方法分组 API 命中
    Map<String, List<CandidateApi>> methodToApis = collectArkTsApisByMethod(report);

    for (Map.Entry<String, List<CandidateApi>> entry : methodToApis.entrySet()) {
        String declaringMethod = entry.getKey();
        List<CandidateApi> methodApis = entry.getValue();

        for (ProfileCombinationRule rule : rules) {
            if (!isSameMethodRule(rule)) continue;

            // 2. 在该方法内匹配规则
            //    要求：规则中每个 requiredApi 都有对应的命中
            List<CandidateApi> matchedApis = matchRuleInMethod(rule, methodApis);

            if (matchedApis.size() < 2) continue;  // 需要至少 2 个 API 才算"联合"

            // 3. 构建 MultiSourceCollaboration 报告
            UnifiedPrivacyReport.MultiSourceCollaboration collab =
                buildRuleMatchedCollaboration(rule, declaringMethod, matchedApis, ...);
            results.add(collab);
        }
    }
}
```

#### 规则匹配：matchRuleInMethod()

```java
// MultiSourceCollaborationAnalyzer.java 第 828-865 行
private static List<CandidateApi> matchRuleInMethod(
        ProfileCombinationRule rule, List<CandidateApi> methodApis) {

    Map<String, CandidateApi> matched = new LinkedHashMap<>();

    // 遍历规则的每个条件
    for (ApiRequirement requirement : rule.requiredApis) {
        List<CandidateApi> requirementMatches = new ArrayList<>();

        for (CandidateApi candidate : methodApis) {
            if (matchesRequirement(candidate, requirement)) {
                requirementMatches.add(candidate);
            }
        }

        // 如果某个条件没有任何命中 → 规则不匹配
        if (requirementMatches.isEmpty()) {
            return new ArrayList<>();
        }

        // 所有满足该条件的 API 都加入结果
        for (CandidateApi candidate : requirementMatches) {
            matched.put(buildCandidateKey(candidate), candidate);
        }
    }

    return new ArrayList<>(matched.values());
}
```

#### matchesRequirement() — 单个条件的匹配

```java
// MultiSourceCollaborationAnalyzer.java 第 867-907 行
private static boolean matchesRequirement(CandidateApi candidate, ApiRequirement requirement) {
    boolean hasAnyCondition = false;

    // 条件 1：api 字段完全匹配
    if (!isBlank(requirement.api)) {
        hasAnyCondition = true;
        String actualApi = buildApiName(candidate.usage);  // "namespace.method"
        if (!matchesText(actualApi, requirement.api)) return false;
    }

    // 条件 2：category 字段匹配（支持通配符）
    if (!isBlank(requirement.category)) {
        hasAnyCondition = true;
        // 例如 requirement.category = "device_identity.*"
        // 会匹配 "device_identity.hardware" 和 "device_identity.software"
        if (!matchesCategory(candidate.category, requirement.category)) return false;
    }

    // 条件 3：namespace 匹配
    if (!isBlank(requirement.namespace)) {
        hasAnyCondition = true;
        if (!matchesText(candidate.usage.namespace, requirement.namespace)) return false;
    }

    // 条件 4：method 匹配
    if (!isBlank(requirement.method)) {
        hasAnyCondition = true;
        if (!matchesText(candidate.usage.method, requirement.method)) return false;
    }

    return hasAnyCondition;
}
```

**matchesCategory 支持通配符：**

```java
// MultiSourceCollaborationAnalyzer.java 第 2000-2014 行
private static boolean matchesCategory(String actual, String expected) {
    String a = actual.trim();
    String e = expected.trim();

    if (e.endsWith(".*")) {
        String prefix = e.substring(0, e.length() - 2);
        // "device_identity.*" → 匹配 "device_identity.hardware"
        //                   → 匹配 "device_identity.software"
        //                   → 不匹配 "device_identity"
        return a.equals(prefix) || a.startsWith(prefix + ".");
    }

    return a.equals(e);
}
```

#### LCA 检测：analyzeLcaByRules()

```java
// MultiSourceCollaborationAnalyzer.java 第 175-247 行
private static List<UnifiedPrivacyReport.MultiSourceCollaboration>
analyzeLcaByRules(UnifiedPrivacyReport report,
        List<ProfileCombinationRule> rules, CallGraph callGraph) {

    // 1. 收集所有匹配规则的 API，按方法分组
    Map<String, List<CandidateApi>> matchedMethodToApis = ...;

    if (matchedMethodToApis.size() < 2) return results;  // 至少 2 个方法

    // 2. 基于 CallGraph 找最低公共祖先
    CGResult cgResult = findLowestCommonAncestorByCG(callGraph,
            new ArrayList<>(matchedMethodToApis.keySet()));

    if (cgResult != null && cgResult.lca != null) {
        // 3. 验证从 LCA 到每个方法的可达性
        List<CandidateApi> reachableApis = verifyReachability(
                callGraph, cgResult.lca, matchedMethodToApis);

        if (reachableApis.size() >= 2) {
            UnifiedPrivacyReport.MultiSourceCollaboration collab =
                buildCgLcaCollaboration(rule, cgResult.lca, ...);
            results.add(collab);
        }
    }

    // 4. 回退：基于调用链路径匹配找 LCA
    ...
}
```

#### LCA 算法：findLowestCommonAncestorByCG()

```java
// MultiSourceCollaborationAnalyzer.java 第 266-378 行
private static CGResult findLowestCommonAncestorByCG(
        CallGraph callGraph, List<String> targetMethods) {

    // Step 1: BFS 从所有入口函数向下，收集 depthFromRoot
    Map<HiFunction, Integer> depthFromRoot = new HashMap<>();
    Deque<HiFunction> queue = new ArrayDeque<>();

    for (HiFunction entry : callGraph.getEntryFunctions()) {
        depthFromRoot.put(entry, 0);
        queue.add(entry);
    }

    while (!queue.isEmpty()) {
        HiFunction current = queue.poll();
        int depth = depthFromRoot.get(current);
        for (HiFunction callee : callGraph.getCalleesByCaller(current)) {
            depthFromRoot.put(callee, depth + 1);
            queue.add(callee);
        }
    }

    // Step 2: 对每个目标函数，反向 BFS 收集祖先集合
    List<Set<HiFunction>> ancestorSets = new ArrayList<>();
    for (HiFunction target : targetFuncs) {
        Set<HiFunction> ancestors = new HashSet<>();
        Deque<HiFunction> bfsQueue = new ArrayDeque<>();
        bfsQueue.add(target);
        ancestors.add(target);

        while (!bfsQueue.isEmpty()) {
            HiFunction current = bfsQueue.poll();
            for (HiFunction caller : callGraph.getCallersByCallee(current)) {
                ancestors.add(caller);
                bfsQueue.add(caller);
            }
        }
        ancestorSets.add(ancestors);
    }

    // Step 3: 从浅到深找共同祖先
    for (int depth = 0; depth <= maxDepth; depth++) {
        for (HiFunction candidate : depthFromRoot.keySet()) {
            if (depthFromRoot.get(candidate) != depth) continue;

            // 检查是否是所有目标函数的祖先
            boolean isAncestorOfAll = true;
            for (Set<HiFunction> ancestors : ancestorSets) {
                if (!ancestors.contains(candidate)) { isAncestorOfAll = false; break; }
            }

            if (isAncestorOfAll) {
                // 找到 LCA：深度最浅的共同祖先
                return new CGResult(candidate, safeFunctionSig(candidate), depth);
            }
        }
    }
    return null;
}
```

**LCA 算法示例：**

```
调用图：
       entry
      /     \
    foo      bar
    |         |
  baz       qux
    |         |
  sink1    sink2

BFS depth:
  entry=0, foo=1, bar=1, baz=2, qux=2, sink1=3, sink2=3

反向 BFS 祖先集：
  sink1 ancestors: {sink1, baz, foo, entry}
  sink2 ancestors: {sink2, qux, bar, entry}

共同祖先按深度：
  depth=0: entry → 是 sink1 和 sink2 的共同祖先 ✓ → LCA = entry
  depth=1: foo, bar → foo 不是 sink2 的祖先，bar 不是 sink1 的祖先
```

---

### SoVulnerabilityScanner — Native SO 分析

**职责：** 调用 angr 符号执行扫描 SO 文件中的隐私 C API。

#### 源码位置

`src/main/java/com/huawei/hisec\SoVulnerabilityScanner.java`

#### 公开入口：scanDirectory()

```java
// SoVulnerabilityScanner.java 第 125-175 行
public NativeScanResult scanDirectory(File targetDirectory) {
    NativeScanResult result = new NativeScanResult();

    // 1. 收集所有 .so 文件
    List<File> soFiles = collectSoFiles(targetDirectory);

    // 2. 逐个扫描
    for (File soFile : soFiles) {
        String soName = soFile.getName();

        // 3. 跳过运行时库
        if (skipRuntimeLibraries && DEFAULT_SKIP_SO_NAMES.contains(soName)) {
            Logger.log("[*] Skip common runtime library: " + soName);
            continue;
        }

        // 4. 调用 Python/angr 扫描
        List<UnifiedPrivacyReport.ApiUsage> usages =
            scanSingleSoFile(soFile, dedupKeys, result.warnings);
        result.nativeApiUsages.addAll(usages);
    }
    return result;
}
```

#### 单个 SO 扫描：scanSingleSoFile()

```java
// SoVulnerabilityScanner.java 第 181-280 行
private List<UnifiedPrivacyReport.ApiUsage> scanSingleSoFile(
        File soFile, Set<String> dedupKeys, List<String> warnings) {

    // 1. 构造 WSL 命令
    String wslSoPath = toWslPath(soFile.getAbsolutePath());
    String wslRulePath = toWslPath(nativeRuleFile.getAbsolutePath());

    ProcessBuilder pb = new ProcessBuilder(
        "wsl.exe", "-d", wslDistro, "--",
        wslPython,      // python3
        wslScanner,     // ~/arkprism/pure_angr_scanner.py
        wslSoPath,
        wslRulePath
    );

    // 2. 启动进程
    Process process = pb.start();

    // 3. 读取 stdout（只读 JSON）
    StringBuilder stdoutBuilder = new StringBuilder();
    try (Scanner outScanner = new Scanner(process.getInputStream(), StandardCharsets.UTF_8)) {
        while (outScanner.hasNextLine()) {
            stdoutBuilder.append(outScanner.nextLine());
        }
    }

    // 4. 从 stdout 中提取 JSON 数组
    String rawStdout = stdoutBuilder.toString().trim();
    String jsonResult = extractJsonArray(rawStdout);

    // 5. 解析 JSON 结果
    ArrayList<JsonNode> hitNodes = mapper.readValue(jsonResult,
            new TypeReference<ArrayList<JsonNode>>() {});

    for (JsonNode item : hitNodes) {
        UnifiedPrivacyReport.ApiUsage usage = convertNativeHitToApiUsage(soFile, item);
        dedupKeys.add(buildDedupKey(usage));
        usages.add(usage);
    }

    return usages;
}
```

**stdout 重定向机制：**

```python
# pure_angr_scanner.py 第 44-45 行
_REAL_STDOUT = sys.stdout
sys.stdout = sys.stderr  # 所有 print 输出到 stderr

# 第 467 行：只有最终 JSON 输出到真正的 stdout
print(json.dumps(results, ensure_ascii=False), file=_REAL_STDOUT, flush=True)
```

这样 Java 读取 `process.getInputStream()` 时只会得到 JSON，不会混入日志。

#### 路径转换：toWslPath()

```java
// SoVulnerabilityScanner.java 第 666-676 行
private String toWslPath(String windowsPath) {
    // D:\Projects\...\libxxx.so → /mnt/d/Projects/.../libxxx.so
    if (abs.matches("^[A-Za-z]:.*")) {
        String drive = abs.substring(0, 1).toLowerCase(Locale.ROOT);
        String rest = abs.substring(2).replace("\\", "/");
        return "/mnt/" + drive + rest;
    }
    return abs.replace("\\", "/");
}
```

---

### PrivacyCatalog — Source/Sink 目录

**职责：** 从 `privacy_apis.json` 加载 source 和 sink API 集合，供数据流分析使用。

#### 源码位置

`src/main/java/com/huawei/hisec\PrivacyCatalog.java`

#### 构造与加载

```java
// PrivacyCatalog.java 第 46-48 行
public PrivacyCatalog(String jsonPath) {
    loadFromJson(jsonPath);
}

// 加载过程：PrivacyCatalog.java 第 153-211 行
private void loadFromJson(String jsonPath) {
    List<PrivacyApiPackage> packages = MAPPER.readValue(
            new File(jsonPath), new TypeReference<List<PrivacyApiPackage>>() {});

    for (PrivacyApiPackage pkg : packages) {
        for (PrivacyApiRule rule : pkg.privacyApis) {
            String fullName = rule.namespace + "." + rule.method;
            String direction = resolveDirection(rule);

            if ("excluded".equals(direction)) continue;

            if ("source".equals(direction) || "both".equals(direction)) {
                sourcePatterns.add(fullName);  // "geoLocationManager.getCurrentLocation"
            }

            if ("sink".equals(direction) || "both".equals(direction)) {
                sinkPatterns.add(fullName);
                sinkPatterns.add("@system:@ohos:" + fullName);  // 两个变体都加
            }
        }
    }
}
```

#### dataDirection 解析：resolveDirection()

```java
// PrivacyCatalog.java 第 220-228 行
private String resolveDirection(PrivacyApiRule rule) {
    // 优先级 1：显式声明
    if (rule.dataDirection != null && !rule.dataDirection.isBlank()) {
        return rule.dataDirection.trim().toLowerCase(Locale.ROOT);
    }

    // 优先级 2：从 profilingCategory 推断
    return inferDirection(rule.profilingCategory);
}

// 推断逻辑：PrivacyCatalog.java 第 234-271 行
private String inferDirection(String profilingCategory) {
    if (profilingCategory == null) return null;
    String lower = profilingCategory.toLowerCase(Locale.ROOT);

    // excluded：非隐私相关的系统信息
    if (lower.equals("device_identity.screen") ||
        lower.equals("device_status.battery")) {
        return "excluded";
    }

    // source：读取隐私数据
    if (lower.startsWith("device_identity.") ||
        lower.startsWith("location") ||
        lower.startsWith("media.") ||
        lower.startsWith("user_data")) {
        return "source";
    }

    // sink：输出/上传数据
    if (lower.startsWith("network.") ||
        lower.startsWith("data_storage")) {
        return "sink";
    }

    return null;
}
```

#### Source API 检测：isSourceApi()

```java
// PrivacyCatalog.java 第 64-89 行
public boolean isSourceApi(HiFile hiFile, CallStmt callStmt) {
    String apiName = hiFile.getFullApiNameByStmt(callStmt);
    String normalized = stripOhosPrefix(apiName);

    // 直接匹配
    if (sourcePatterns.contains(normalized)) return true;
    if (sourcePatterns.contains(apiName)) return true;

    // 模块前缀匹配（multimedia.audio == audio）
    int lastDot = normalized.lastIndexOf('.');
    if (lastDot > 0) {
        String methodFull = normalized.substring(lastDot);  // ".getCurrentLocation"
        for (String pattern : sourcePatterns) {
            int patLastDot = pattern.lastIndexOf('.');
            if (patLastDot > 0) {
                String patMethod = pattern.substring(patLastDot);  // ".getCurrentLocation"
                if (methodFull.equals(patMethod)) return true;
            }
        }
    }

    return false;
}
```

#### Def-Use 分析：isValueUsed()

```java
// PrivacyCatalog.java 第 115-122 行
public boolean isValueUsed(Stmt stmt) {
    try {
        // 华为分析工具提供 getUses() API，返回语句使用的所有值
        var uses = stmt.getUses();
        return uses != null && !uses.isEmpty();
    } catch (Throwable t) {
        return true;  // 失败时保守放过
    }
}
```

**原理：** 如果一个赋值语句的定义从未被任何其他语句使用，则该赋值是死代码。

```java
// 示例：
PERMISSION = "ohos.permission.LOCATION"  // 定义了 PERMISSION
// 但之后没有任何地方引用 PERMISSION
// → getUses() 返回空 → isValueUsed() = false → 置信度降为 low
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