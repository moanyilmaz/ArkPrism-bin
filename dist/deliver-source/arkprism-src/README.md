# ArkPrism 二进制隐私API分析工具 - 源码包

## 1. 项目概述

ArkPrism 是一个面向 HarmonyOS 应用（.abc 字节码 + .so 原生库）的静态隐私敏感 API 分析工具。本包包含完整的 Java 源代码，可用于审计、验证和二次开发。

**核心算法**: CAIR (Conflict-Aware Identity Resolution) v3e  
**版本**: commit b0ee177

## 2. 目录结构

```
arkprism-src/
├── README.md                          # 本文档
├── pom.xml                            # Maven 构建配置
├── settings.xml                       # Maven 仓库配置（华为内部源）
├── src/
│   └── main/java/com/huawei/hisec/    # Java 源码
│       ├── Main.java                  # 程序入口
│       ├── PreciseSensitiveApiScanner.java  # 敏感API扫描器
│       ├── CaiResolver.java           # CAIR 身份解析算法
│       ├── AmbiguityModel.java        # 歧义评估模型
│       ├── NamespaceResolver.java     # 命名空间解析
│       ├── NamePathMatcher.java       # 名称路径匹配
│       ├── PrivacyCatalog.java        # 隐私API规则目录
│       ├── PrivacyApiRule.java        # 规则数据结构
│       ├── ScannerUtils.java          # 扫描工具函数
│       ├── CallGraphExplorer.java     # 调用图构建
│       ├── ReachabilityAnalyzer.java  # 可达性分析
│       ├── DataFlowExplorer.java      # 数据流分析
│       ├── MultiSourceCollaborationAnalyzer.java  # 多源协作分析
│       ├── SoVulnerabilityScanner.java  # Native SO 扫描器
│       ├── UnifiedPrivacyReport.java  # 统一报告生成
│       └── Logger.java                # 日志工具
├── config/
│   ├── privacy_apis.json              # ArkTS 隐私API规则（64个包，826条）
│   ├── native_privacy_apis.json       # Native C API规则（70条）
│   └── profile_combinations.json      # 多源协作规则
└── scripts/
    ├── compare_apis.py                # API规则对比工具
    ├── expand_native_rules.py         # Native规则扩展
    ├── fix_data_direction.js          # 数据方向修正
    ├── fix_native_rules.py            # Native规则修正
    ├── patch_privacy_apis.py          # 规则补丁工具
    ├── regenerate_native_rules.py     # 重新生成Native规则
    ├── translate_comments.py          # 规则注释翻译
    └── validate_native_rules.py       # Native规则验证
```

## 3. 核心算法说明

### 3.1 CAIR (Conflict-Aware Identity Resolution)

CAIR 解决二进制分析中的 API 身份歧义问题。在 .abc 字节码中，API 调用形式为 `v5.<method>(args)`，接收者对象的类型信息可能不完整。CAIR 通过多证据融合解析 API 身份：

**输入**: `VirtualCall: v.recv.<method>(args)`  
**输出**: `Resolved API Identity: namespace.method`

**证据来源**:
- **PTA (Pointer Analysis)**: Andersen 风格指针分析推断接收者类型
- **PATH_TOKEN**: 调用链路径上的标识符信息
- **NAMESPACE_IMPORT**: `@ohos:*` 导入语句关联
- **API_MAP**: 直接规则匹配

**歧义评估**: 当多个候选身份冲突时，CAIR 使用一致性调整评分 (consistency-adjusted score) 选择最可信的身份。

**身份模型**: `Id(v) = ⟨Pkg, Ns, Recv, Mem, Acc⟩`
- Pkg: 系统包名 (如 `@kit.NetworkKit`)
- Ns: 命名空间 (如 `connection`)
- Recv: 接收者类型
- Mem: 方法名
- Acc: 访问方式 (direct/invoke/virtual)

### 3.2 污点传播 (SrcBind + T1-T5)

检测从隐私 source 到网络 sink 的数据流：
- **SrcBind(call, cb, param)**: 绑定 API 调用与回调参数
- **T1-T5 转移规则**: 定义参数间的数据传播关系

### 3.3 多源协作

检测多个隐私数据源汇聚到同一网络出口的行为模式，通过 `profile_combinations.json` 定义协作规则。

## 4. 编译与构建

### 4.1 前置条件

| 组件 | 版本要求 | 说明 |
|------|----------|------|
| JDK | 21+ | 编译和运行 |
| Maven | 3.8+ | 构建工具 |
| HiAnalyzer JAR | 26.0.0.21 | 依赖库（需手动安装到本地仓库） |

### 4.2 编译步骤

**方式一：使用 Maven（推荐）**

```bash
# 安装 HiAnalyzer 依赖到本地仓库
mvn install:install-file \
    -Dfile=hisec-enhance-app-analyzer-all-in-one-26.0.0.21.jar \
    -DgroupId=com.huawei.hisec \
    -DartifactId=hisec-enhance-app-analyzer-all-in-one \
    -Dversion=26.0.0.21 \
    -Dpackaging=jar

# 编译项目
mvn compile

# 打包
mvn package
```

**方式二：使用 javac 直接编译**

```bash
# 创建输出目录
mkdir -p target/classes

# 编译所有源码
javac -d target/classes \
    -cp "lib/hisec-enhance-app-analyzer-all-in-one-26.0.0.21.jar:lib/jackson-*.jar:lib/slf4j-*.jar" \
    src/main/java/com/huawei/hisec/*.java

# 打包为 JAR
cd target/classes
jar cf ../../dist/ArkPrism-bin/lib/arkprism-main.jar com/
```

### 4.3 构建可运行包

编译完成后，使用 `package.sh` 构建完整的可运行包：

```bash
bash package.sh
```

输出目录：`dist/ArkPrism-bin/`

## 5. 代码结构关系

```
Main.java                    程序入口，参数解析，批量调度
    ↓
PreciseSensitiveApiScanner   核心扫描引擎
    ├── PrivacyCatalog       加载 privacy_apis.json 规则
    ├── CaiResolver          CAIR 身份解析
    │   ├── AmbiguityModel   歧义评估
    │   ├── NamespaceResolver 命名空间解析
    │   └── NamePathMatcher  名称路径匹配
    ├── CallGraphExplorer    调用图构建
    ├── ReachabilityAnalyzer 可达性分析
    └── ScannerUtils         工具函数
    ↓
DataFlowExplorer             数据流分析（source → sink）
MultiSourceCollaborationAnalyzer  多源协作检测
SoVulnerabilityScanner       Native SO 扫描（调用 angr）
    ↓
UnifiedPrivacyReport         统一报告生成
```

## 6. 配置文件说明

### privacy_apis.json

ArkTS 隐私API规则定义，格式如下：

```json
[{
  "systemPackage": "@kit.NetworkKit",
  "privacyApis": [{
    "directCall": true,
    "namespace": "connection",
    "method": "getAllNets",
    "permission": "ohos.permission.GET_NETWORK_INFO",
    "profilingCategory": "network.connectivity",
    "ohos_module": "@ohos:net.connection",
    "dataDirection": "source"
  }]
}]
```

**字段说明**:
- `systemPackage`: HarmonyOS Kit 包名
- `namespace`: API 命名空间
- `method`: 方法名
- `directCall`: 是否为直接调用（vs 属性访问）
- `permission`: 所需权限
- `profilingCategory`: 隐私分类
- `ohos_module`: 对应的 @ohos 导入模块
- `dataDirection`: 数据方向（source/sink/both）

### native_privacy_apis.json

Native C/C++ API 规则定义，格式如下：

```json
{
  "nativeApis": [{
    "symbol": "OH_GetDeviceType",
    "prototype": "const char *OH_GetDeviceType(void)",
    "category": "device_info",
    "profilingCategory": "device_identity.hardware",
    "apiPackage": "OpenHarmony.Native.DeviceInfo",
    "matchModes": ["import_symbol", "string_reference"],
    "dataDirection": "source"
  }]
}
```

### profile_combinations.json

多源协作规则，定义哪些隐私数据源的组合构成协作行为。

## 7. 关键类说明

| 类名 | 行数 | 职责 |
|------|------|------|
| PreciseSensitiveApiScanner | ~1500 | 核心扫描：IR解析、API匹配、CAIR调用、调用链提取 |
| CaiResolver | ~800 | CAIR算法：多证据融合、候选生成、歧义消解 |
| CallGraphExplorer | ~600 | 调用图：函数间调用关系、入口函数识别 |
| DataFlowExplorer | ~500 | 数据流：source→sink传播、SrcBind绑定 |
| MultiSourceCollaborationAnalyzer | ~400 | 多源协作：profile匹配、协作检测 |
| UnifiedPrivacyReport | ~300 | 报告：JSON输出、batch汇总 |
| SoVulnerabilityScanner | ~200 | Native扫描：angr调用、SO分析 |
| AmbiguityModel | ~150 | 歧义模型：一致性评分 |
| NamespaceResolver | ~200 | 命名空间解析：import语句关联 |

## 8. 运行参数

```bash
java -cp "lib/*" com.huawei.hisec.Main \
    <input_dir>          \   # HAP 解包目录（批量模式）或单个 HAP 目录
    <privacy_apis_json>  \   # ArkTS 隐私API规则文件路径
    <output_dir>         \   # 输出目录
    <profile_json>       \   # 多源协作规则文件路径
    <native_apis_json>       # Native API规则文件路径
```

**JVM 参数建议**:
- 小规模（<10 HAP）: `-Xms4g -Xmx8g -Xss512m`
- 中规模（10-50 HAP）: `-Xms8g -Xmx16g -Xss512m`
- 大规模（50+ HAP）: `-Xms16g -Xmx32g -Xss512m`

## 9. 评估结果

在 8-HAP 基准测试上（5个华为二进制 + 3个开源项目）：

| 指标 | 数值 |
|------|------|
| 精确率 (Precision) | 99.0% |
| 召回率 (Recall) | 96.3% |
| F1 分数 | 97.6% |

详见配套的 `deliver-binary/` 目录中的评估报告。
