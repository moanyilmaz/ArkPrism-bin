# 第三方库可达性验证（2026-11-02）

## 行为回归

使用 OpenHarmony SDK 的 es2abc 将 `tests/fixtures/library-reachability/` 中的 JavaScript 模块实际编译成 ABC，再运行完整的 Main → 扫描 → 过滤 → JSON 报告流程。20 项检查通过。

| 场景 | 验证结果 |
|---|---|
| 应用生命周期调用另一 ABC 的库导出函数 | 保留被调用的 `used()`，排除同一库中未调用的 `unused()`，输出应用入口到库的路径。 |
| 应用未调用库 | 排除两个库调用点。 |
| 应用自身调用同一个敏感 API | 保留应用命中，仍排除库中两个未调用的调用点。 |
| 将导入的库函数注册为回调 | 该回调的 API 标为 reachable，不能解析的其他可能路径保持 unknown。 |
| 未解析的动态插件调用 | 两个库命中保持 unknown，未强制排除。 |
| 应用 → 转调模块 → 库，三个独立 ABC | 保留三段入口路径，并排除未使用函数。 |
| 显式关闭过滤 | 两个库命中均保留。 |
| 多应用批量输入 | 各应用独立分析，不按其他应用的同名 API 推断可达性。 |
| ABC 损坏 | 报告警告，库命中保留 unknown。 |
| 应用目录内的 oh_modules 记录 | 识别库来源，正确保留、排除对应调用点。 |
| 两个独立 entry 应用具有相同 bundleName | 仍分别生成报告，不合并为同一个应用。 |

同时检查报告的 API 数、调用链数、链索引及警告。验证 Native SO 不在本次功能范围内。

在仓库根目录复现（完整 JDK 21、OpenHarmony SDK 的 es2abc）：

```powershell
.\scripts\test-library-reachability.ps1 -JdkHome "C:\path\to\jdk-21" -Es2abc "C:\path\to\es2abc.exe"
```

先按 README 解压最新版发行包。脚本从其中读取 8 个依赖 JAR，自行编译当前源码，不使用发行包的主 JAR；输入、日志和报告写入 `target/reachability-tests-*/`。

## 发行包功能样例

发行包中提供 `input-reachability/`，包含已调用库、未调用库、同名 API、回调、动态调用、三模块转调六个应用样例。从发行目录运行：

```powershell
.\run.bat ".\input-reachability"
```

检查各报告的 `libraryFiltering`、库命中的 `entryReachability` 及调用链。源文件保存在仓库的 `tests/fixtures/library-reachability/`。

## 判定范围

库来源按模块路径和 ABC 记录识别，入口使用模块初始化与常见生命周期/事件模型。支持已解析的调用图边、模块限定的具名导入、局部函数别名和函数参数回调。父级相对导入、默认导出别名、动态分派等未能解析时保留不确定记录；库的潜在框架回调和初始化代码也保留。静态可达表示存在可能调用路径，不等于运行时一定执行。

## 本地真实 ABC 回归

11 个按应用隔离的本地 ABC 全部解析成功，报告警告为 0；共 180 条 API 命中记录、242 条调用链。已检查所有调用链 API 索引与报告计数。此批输入未识别到独立第三方模块，用于检查普通应用扫描；库过滤行为由上面的真实编译 ABC 样例验证。

| 应用 | API 命中 | 调用链 |
|---|---:|---:|
| 01-STUFFS_NEXT-preview | 18 | 19 |
| 02-STUFFS_NEXT-build | 18 | 19 |
| 03-YX_Sports | 1 | 1 |
| 04-Wechat_HarmonyOS | 22 | 23 |
| 05-legado-Harmony-main | 20 | 24 |
| 06-C5765880207855243995_1.5.41 | 1 | 1 |
| 07-C6917596277126662423_1.0.0 | 32 | 41 |
| 08-C6917601515137710787_1.0.0 | 1 | 1 |
| 09-C6917602215994202990_1.0.0 | 32 | 54 |
| 10-C6917602221479724885_1.0.0 | 34 | 58 |
| 11-FlameChase | 1 | 1 |
