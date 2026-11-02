# ArkPrism 运行指南

ArkPrism 分析 HarmonyOS / OpenHarmony 应用的 ArkTS 字节码（`.abc`）和 Native 库（`.so`），输出敏感 API 使用记录与调用链。可以直接使用发行包，也可以在 IntelliJ IDEA 中运行和调试源码。

## 1. 下载最新版

- [最新版工具 ZIP（Windows x64）](https://github.com/moanyilmaz/ArkPrism-bin/raw/refs/heads/delivery/latest-runnable-20261012/dist/ArkPrism-bin-latest-20261102.zip)
- [源码分支](https://github.com/moanyilmaz/ArkPrism-bin/tree/delivery/latest-runnable-20261012)

Windows x64 发行包自带 Java 21 运行时，直接运行无需另装 Java。源码编译需要完整的 **JDK 21**，包内 `runtime/` 不能作为编译用 JDK。

## 2. 准备输入

先把 HAP 作为 ZIP 解压，使用解包后的应用目录作为输入。如果只有 ABC 文件，将它放入单独的目录，例如 `input/MyApp/ets/modules.abc`。

批量分析时，每个应用放在 `input/` 下独立的子目录中。仅分析 ABC 不需要 WSL 或 angr；输入包含 SO 时，按第 5 节准备 Native 环境。

## 3. 直接运行发行包

解压 ZIP 后，进入包含 `run.bat` 的目录。将应用目录放入 `input/`，双击 `run.bat`，或者在 PowerShell 中执行：

```powershell
.\run.bat
```

分析指定的应用解包目录：

```powershell
.\run.bat "C:\path\to\unpacked-app"
```

运行包内的 ABC 样例：

```powershell
.\run.bat ".\input-8hap\STUFFS_NEXT-master"
```

结果保存在发行目录的 `out/` 中。每次运行生成独立目录，包含应用的 `*_privacy_report.json` 和日志；批量运行还会生成 `batch_summary.json`。

启动脚本默认初始堆为 4 GB、最大堆为 16 GB。内存较小的机器可以编辑 `run.bat`，把 JVM 参数改为 `-Xms256m -Xmx3g -Xss16m`；较大应用可能需要更多内存。

## 4. 在 IntelliJ IDEA 中运行源码

### 4.1 下载源码和依赖

```powershell
git clone --branch delivery/latest-runnable-20261012 --single-branch https://github.com/moanyilmaz/ArkPrism-bin.git
cd ArkPrism-bin
Expand-Archive -LiteralPath ".\dist\ArkPrism-bin-latest-20261102.zip" -DestinationPath ".\dist"
```

解压后应有 `dist/ArkPrism-bin-latest-20261102/lib/`。使用已有仓库时，切换到对应分支后解压 ZIP 即可。

### 4.2 创建普通 Java 工程

`pom.xml` 引用了华为分析库，公网 Maven 可能无法下载。使用发行包自带的依赖，可以通过普通 Java 工程运行源码：

1. 选择 **File → New → Project from Existing Sources**，选中仓库根目录。欢迎页也可以按 `Ctrl+Shift+A`，搜索 `project from existing sources`。
2. 选择 **Create project from existing sources**，使用 IDEA 自带构建；跳过自动检测到的 Maven 框架，不添加为 Maven 项目。
3. 只选择 `src/main/java` 为源码根目录，不导入 `dist/deliver-source` 下的历史源码。若导入向导自动选中库，取消 `arkprism-main.jar`。
4. 选择完整的 **JDK 21**。在 **Project Structure → Project / Modules** 中，将 SDK 和语言级别设为 Java 21。
5. 在 **Project Structure → Modules → Dependencies → + → JARs or directories** 中，选择 `dist/ArkPrism-bin-latest-20261102/lib/` 下除 `arkprism-main.jar` 外的 **8 个 JAR 文件**，Scope 设为 **Compile**。不要直接添加整个 `lib` 目录，以免把主程序字节码一起加入源码模块。

如果已作为 Maven 项目导入，先在 Maven 工具窗口中解除该项目的链接（Unlink Maven Project），再配置普通 Java 模块。Maven 重新同步会按 `pom.xml` 重建依赖，覆盖手动添加的库。

可参考 JetBrains 官方的[从现有源码创建工程](https://www.jetbrains.com/help/idea/import-project-or-module-wizard.html)和[模块依赖配置](https://www.jetbrains.com/help/idea/working-with-module-dependencies.html)。

### 4.3 配置 Run / Debug

打开 **Run → Edit Configurations → + → Application**，填写：

| 配置项 | 内容 |
|---|---|
| Name | `ArkPrism` |
| Main class | `com.huawei.hisec.Main` |
| Use classpath of module | 当前源码所在的 Java 模块 |
| JDK | Java 21 |
| Working directory | 仓库根目录的绝对路径，例如 `E:\Codex\Arkprism-bin` |
| VM options | `-Xms256m -Xmx3g -Xss16m` |
| Program arguments | `dist/ArkPrism-bin-latest-20261102/input-8hap/STUFFS_NEXT-master` |

若 VM options 不显示，在 **Modify options** 中添加。Working directory 必须是包含根目录 `config/` 的仓库目录。

点击 **Run** 运行；点击 **Debug** 可在 `Main.java` 或扫描器中设置断点。结果保存在仓库根目录的 `out/` 中。[IDEA Application 配置说明](https://www.jetbrains.com/help/idea/run-debug-configuration-java-application.html)

换成自己的输入时，在 Program arguments 中填写应用解包目录，带空格的路径加双引号：

```text
"E:\path\to\unpacked-app"
```

需要自定义配置文件或输出目录时，按下面顺序填写全部五个参数：

```text
"E:\path\to\unpacked-app" "config/privacy_apis.json" "out" "config/profile_combinations.json" "config/native_privacy_apis.json"
```

不填写参数时，源码入口默认查找仓库根目录的 `benchmark_input/`；发行包启动脚本则默认使用 `input/`。建议显式填写输入目录。

## 5. Native SO 分析（按需配置）

Windows 默认通过 WSL 的 **Ubuntu-22.04** 调用 Python 扫描器。需要准备项目兼容的 angr 环境，将发行包的 `python_tools/pure_angr_scanner.py` 部署到 WSL，例如 `~/arkprism/pure_angr_scanner.py`。

Python 或脚本位置不同，可以设置环境变量；IDEA 中填写到 Application 配置的 **Environment variables**，命令行中则在运行前设置：

```powershell
$env:ARKPRISM_WSL_PYTHON = "/home/youruser/venv/bin/python"
$env:ARKPRISM_WSL_SCANNER = "/home/youruser/arkprism/pure_angr_scanner.py"
.\run.bat "C:\path\to\unpacked-app"
```

Linux 需要系统 Java 21 及 Python/angr，包内 Windows 运行时不适用。从发行目录运行：

```bash
export ARKPRISM_NATIVE_MODE=native
export ARKPRISM_WSL_PYTHON=python3
export ARKPRISM_WSL_SCANNER="$PWD/python_tools/pure_angr_scanner.py"
bash run.sh /path/to/unpacked-app
```

## 6. 第三方库 API 可达性过滤

默认开启。将同一应用的 entry、feature 和第三方模块放在同一个应用目录内，不同应用分别放在批量输入目录的各个子目录下；不要把库模块作为独立应用输入。

工具按应用联合加载 ABC，以应用模块初始化、常见 Ability/ArkUI 生命周期和事件入口为起点，结合调用图、显式模块导入及已解析的函数回调，判断库内具体 API 调用点是否可达。库来源由 `@scope` 模块目录及 ABC 的 `oh_modules` / `node_modules` 记录识别。

- 可达：保留 API，并输出 `entryReachability.path` 作为入口路径证据。
- 不可达：排除库内该调用点，并更新 API、调用链和统计；应用自身的 API 不受该过滤影响。
- 无法确定：保留并标记 `entryReachability.status = "unknown"`，例如缺失 ABC、未解析的动态调用、库生命周期或初始化代码。来源无法识别的库也不会强制排除。

过滤按应用隔离，不再根据其他应用是否调用同名 API 决定保留。报告顶层的 `libraryFiltering` 给出排除数、可达保留数与不确定保留数。该功能作用于 ArkTS ABC，不对 Native SO 作应用入口可达性判定。

IDEA 中可在 VM options 加入 `-Dfilter.library.apis=false` 关闭过滤；发行包可在启动脚本的 Java 命令中、主类之前添加此参数。

验证包内功能样例（已调用库、未调用库、同名 API、回调、动态调用、跨模块转调）：

```powershell
.\run.bat ".\input-reachability"
```

回归脚本与验证结果见 [测试说明](tests/library-reachability-validation.md)。跨模块导出别名、父级相对导入及动态分派尚未完全建模时会保留不确定记录；静态可达表示可能被执行。

## 7. 常见问题

| 问题 | 处理方法 |
|---|---|
| Maven 无法下载华为依赖 | 按第 4 节使用普通 Java 工程，手动添加发行包的 8 个依赖 JAR。 |
| `package ... does not exist` / `ClassNotFoundException` | 检查依赖是否添加到正确模块，Scope 是否为 Compile，运行配置是否选择该模块。 |
| 找不到 `Main` 或提示重复类 | 将 `src/main/java` 标记为 Sources Root；排除历史源码目录，移除源码模块中的 `arkprism-main.jar`。 |
| `UnsupportedClassVersionError` / `invalid target release: 21` | 将 Project SDK、Module SDK 和运行配置的 JDK 都设为 Java 21。 |
| 找不到输入或规则文件 | 检查 Program arguments 与 Working directory；输入必须是包含 ABC/SO 的目录。 |
| 内存不足 | 调整 `-Xmx`，或将应用拆成较小批次顺序运行。 |
| SO 分析失败 | 检查 WSL/angr、Python 和扫描器路径；查看报告中的 warnings 与运行日志。 |

最新版已使用 11 个本地 ABC 完成批量验证，全部成功解析，无报告警告；Native SO 本次未做端到端验证。IFDS 污点分析默认关闭，报告中 `dataSinks` 为空不能用于判断是否存在数据外传路径。
