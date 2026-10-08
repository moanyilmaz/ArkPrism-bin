# ArkPrism - HarmonyOS 隐私 API 静态分析工具（源码包）

## 1. 项目概述

ArkPrism 是一个面向 HarmonyOS 应用（.abc 字节码 + .so 原生库）的静态隐私敏感 API 分析工具。本包包含完整的 Java 源代码，可用于审计、验证和二次开发。

**版本**: PTA-gated Scanner (2026-09-20)
**评估结果**: 20 应用 benchmark — P=99.5%, R=97.3%, F1=98.4%

## 2. 目录结构

```
arkprism-src/
├── README.md                          # 本文档
├── SETUP.md                           # 部署配置指南
├── src/
│   └── main/java/com/huawei/hisec/    # Java 源码（25 个文件）
│       ├── Main.java                  # 程序入口
│       ├── PreciseSensitiveApiScanner.java  # 确定性敏感API扫描器（核心）
│       ├── NamespaceResolver.java     # 命名空间解析（含 PTA 集成）
│       ├── IndirectCallProbe.java     # 间接调用分析探针
│       ├── CaiResolver.java           # CAIR 身份解析算法
│       ├── AmbiguityModel.java        # 歧义评估模型
│       ├── NamePathMatcher.java       # 名称路径匹配
│       ├── PrivacyCatalog.java        # 隐私API规则目录
│       ├── PrivacyApiRule.java        # 规则数据结构
│       ├── PrivacyApiConfigLoader.java # 规则配置加载器
│       ├── ScannerUtils.java          # 扫描工具函数
│       ├── CallGraphExplorer.java     # 调用图构建
│       ├── ReachabilityAnalyzer.java  # 可达性分析
│       ├── DataFlowExplorer.java      # 数据流分析
│       ├── MultiSourceCollaborationAnalyzer.java  # 多源协作分析
│       ├── SdkFactoryGraph.java       # SDK 工厂图
│       ├── SdkFactoryVersionGate.java # SDK 版本门控
│       ├── BindingExperimentTrace.java # 绑定实验追踪
│       ├── SoVulnerabilityScanner.java  # Native SO 扫描器
│       ├── UnifiedPrivacyReport.java  # 统一报告生成
│       ├── Logger.java                # 日志工具
│       ├── ArgProbe.java              # 参数探针
│       ├── BaselineAnalyzer.java      # 基线分析器
│       ├── FieldMapProbe.java         # 字段映射探针
│       └── HiAnalyzerProbe.java       # HiAnalyzer 探针
├── config/
│   ├── privacy_apis.json              # ArkTS 隐私API规则
│   ├── native_privacy_apis.json       # Native C API规则
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

## 3. 编译方法

### 前置条件

- JDK 21+
- HiAnalyzer 依赖 jar 包（需从二进制交付包 `lib/` 目录获取）

### 编译步骤

```bash
# 1. 将 HiAnalyzer 依赖 jar 包放入 lib/ 目录
mkdir -p lib
cp /path/to/ArkPrism-bin/lib/*.jar lib/

# 2. 编译所有源码
mkdir -p build
javac -encoding UTF-8 \
    -cp "lib/hisec-enhance-app-analyzer-all-in-one-26.0.0.21.jar:lib/jackson-annotations-2.18.2.jar:lib/jackson-core-2.18.2.jar:lib/jackson-databind-2.18.2.jar:lib/slf4j-api-1.7.36.jar:lib/slf4j-simple-1.7.36.jar" \
    -d build \
    src/main/java/com/huawei/hisec/*.java

# 3. 打包为主 jar
jar cf arkprism-main.jar -C build .

# 4. 运行
java -Xms4g -Xmx16g -Xss512m \
    -cp "lib/hisec-enhance-app-analyzer-all-in-one-26.0.0.21.jar:lib/jackson-annotations-2.18.2.jar:lib/jackson-core-2.18.2.jar:lib/jackson-databind-2.18.2.jar:arkprism-main.jar:lib/slf4j-api-1.7.36.jar:lib/slf4j-simple-1.7.36.jar" \
    com.huawei.hisec.Main \
    <input_dir> \
    config/privacy_apis.json \
    <output_dir> \
    config/profile_combinations.json \
    config/native_privacy_apis.json
```

> **注意**: Windows 下 classpath 分隔符用 `;`，Linux/macOS 用 `:`。

## 4. 核心算法说明

### 确定性扫描器 (PreciseSensitiveApiScanner)

基于 HiAnalyzer 的 `getAllStmtApiNameMap()` 和 `getAllStmtFieldNameMap()` 做确定性 API 匹配，包含以下关键机制：

- **API_MAP 匹配**: 通过 HiAnalyzer 的语句-API名称映射直接匹配
- **FIELD_MAP 匹配**: 通过字段访问路径匹配（如 `vN = vN.sdkApiVersion`）
- **@bundle 方法名兜底**: 当方法名匹配但接收者解析为 @bundle 时，检查模块导入 + PTA 确认
- **GENERIC_METHOD_BLACKLIST**: 通用方法名黑名单，阻止方法名-only 匹配产生 FP
- **报告级去重**: 基于 `apiSignature + stmtIndex` 去重，避免同一调用点被重复计数
- **模糊匹配防护**: pathNamespace 长度 >= 3 才允许子字符串匹配；all-path-tokens 循环仅限 @bundle/@internal

### PTA 集成 (NamespaceResolver)

集成 Andersen 指针分析，用于 @bundle 路径的方法名匹配验证：
- 当方法名在黑名单中但模块已导入时，通过 PTA 候选集确认接收者类型
- PTA 返回空候选集时不接受匹配（保守策略，可能产生 FN）

## 5. 输入输出

### 输入

- HAP 包解压后的目录，包含 `.abc` 字节码文件
- 目录结构: `input/<app_name>/<hap_name>/...`

### 输出

- JSON 格式的隐私检测报告: `<output_dir>/<app_name>/<app_name>_<timestamp>/<app_name>_privacy_report.json`

## 6. 评估结果

### 20 应用 Benchmark (2026-09-20)

| 指标 | 值 |
|------|-----|
| TP | 616 |
| FP | 3 |
| FN | 17 |
| Precision | 99.5% |
| Recall | 97.3% |
| F1 | 98.4% |

剩余 3 个 FP 和 17 个 FN 均为 HiAnalyzer 工具自身的结构性限制（按字段名解析、异步回调无法跟踪、@bundle 路径解析）。
