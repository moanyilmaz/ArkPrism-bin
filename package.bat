@echo off
REM ============================================================
REM  ArkPrism Binary Analyzer - Package Script
REM  Builds a self-contained distribution package for deployment.
REM
REM  Usage:
REM    package.bat              Build package (default output: dist/ArkPrism-bin)
REM    package.bat <output_dir> Build package to custom output directory
REM ============================================================

setlocal enabledelayedexpansion

set "PROJECT_DIR=%~dp0"
set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
set "OUTPUT_DIR=%~1"
if "%OUTPUT_DIR%"=="" set "OUTPUT_DIR=%PROJECT_DIR%\dist\ArkPrism-bin"

echo ======================================================
echo  ArkPrism Package Builder
echo ======================================================
echo  Project:  %PROJECT_DIR%
echo  Output:   %OUTPUT_DIR%
echo.

REM ---- 1. Create output directory structure ----
echo [1/6] Creating directory structure...
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
if not exist "%OUTPUT_DIR%\lib" mkdir "%OUTPUT_DIR%\lib"
if not exist "%OUTPUT_DIR%\config" mkdir "%OUTPUT_DIR%\config"
if not exist "%OUTPUT_DIR%\python_tools" mkdir "%OUTPUT_DIR%\python_tools"
if not exist "%OUTPUT_DIR%\input" mkdir "%OUTPUT_DIR%\input"

REM ---- 2. Compile project ----
echo [2/6] Compiling project...
where mvn >nul 2>&1
if !errorlevel! equ 0 (
    echo   Using Maven to compile...
    pushd "%PROJECT_DIR%"
    call mvn compile -q
    if !errorlevel! neq 0 (
        echo   [ERROR] Maven compile failed!
        popd
        exit /b 1
    )
    popd
) else (
    echo   Maven not found, checking existing compiled classes...
    if not exist "%PROJECT_DIR%\target\classes\com\huawei\hisec\Main.class" (
        echo   [ERROR] No compiled classes found. Please install Maven or compile in IDEA first.
        exit /b 1
    )
    echo   Found existing compiled classes.
)

REM ---- 3. Build main JAR ----
echo [3/6] Building ArkPrism main JAR...
set "MAIN_JAR=%OUTPUT_DIR%\lib\arkprism-main.jar"

REM Create temporary manifest
set "MANIFEST_FILE=%TEMP%\arkprism-manifest-%RANDOM%.mf"
echo Main-Class: com.huawei.hisec.Main> "%MANIFEST_FILE%"

pushd "%PROJECT_DIR%\target\classes"
jar cfm "%MAIN_JAR%" "%MANIFEST_FILE%" com/
popd
del "%MANIFEST_FILE%" 2>nul

echo   Created: %MAIN_JAR%

REM ---- 4. Copy dependency JARs ----
echo [4/6] Copying dependency JARs...

REM Copy from project lib/ directory
set "DEP_COPIED=0"
for %%F in ("%PROJECT_DIR%\lib\*.jar") do (
    copy /Y "%%F" "%OUTPUT_DIR%\lib\" >nul
    set /a DEP_COPIED+=1
)

REM Also copy from dist lib if available (for hisec-multi-language etc.)
for %%F in ("%PROJECT_DIR%\dist\ArkPrism-bin\lib\*.jar") do (
    copy /Y "%%F" "%OUTPUT_DIR%\lib\" >nul
    set /a DEP_COPIED+=1
)

echo   Copied !DEP_COPIED! JAR files.

REM ---- 5. Copy config files ----
echo [5/6] Copying config files...
copy /Y "%PROJECT_DIR%\config\privacy_apis.json" "%OUTPUT_DIR%\config\" >nul
copy /Y "%PROJECT_DIR%\config\native_privacy_apis.json" "%OUTPUT_DIR%\config\" >nul
if exist "%PROJECT_DIR%\config\profile_combinations.json" (
    copy /Y "%PROJECT_DIR%\config\profile_combinations.json" "%OUTPUT_DIR%\config\" >nul
)
echo   Config files synced.

REM ---- 6. Copy Python tools and scripts ----
echo [6/6] Copying Python tools and run scripts...
copy /Y "%PROJECT_DIR%\src\main\python\pure_angr_scanner.py" "%OUTPUT_DIR%\python_tools\" >nul 2>nul
if not exist "%OUTPUT_DIR%\python_tools\pure_angr_scanner.py" (
    REM Fallback: copy from existing dist
    if exist "%PROJECT_DIR%\dist\ArkPrism-bin\python_tools\pure_angr_scanner.py" (
        copy /Y "%PROJECT_DIR%\dist\ArkPrism-bin\python_tools\pure_angr_scanner.py" "%OUTPUT_DIR%\python_tools\" >nul
    )
)

REM Generate run.bat
call :generate_run_bat "%OUTPUT_DIR%"
REM Generate run.sh
call :generate_run_sh "%OUTPUT_DIR%"
REM Generate SETUP.md
call :generate_setup_doc "%OUTPUT_DIR%"

echo.
echo ======================================================
echo  Package built successfully!
echo  Output: %OUTPUT_DIR%
echo ======================================================
echo.
echo  Next steps:
echo    1. Copy %OUTPUT_DIR% to target machine
echo    2. Follow SETUP.md for environment setup
echo    3. Place HAP directories in input/
echo    4. Run: run.bat
echo.

endlocal
exit /b 0

REM ============================================================
REM  Subroutine: Generate run.bat
REM ============================================================
:generate_run_bat
set "DIR=%~1"

(
echo @echo off
REM ArkPrism - HarmonyOS Privacy API Analyzer
REM
REM Usage:
REM   run.bat                     - Run with default input/ directory ^(batch mode^)
REM   run.bat ^<hap_dir^>           - Run with a single HAP directory
REM
REM Requirements:
REM   - Java 21 or higher
REM   - Python 3.8+ with angr ^(in WSL, for native SO analysis^)

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

set "INPUT_DIR=%SCRIPT_DIR%\input"
set "OUTPUT_DIR=%SCRIPT_DIR%\out"
set "CONFIG_DIR=%SCRIPT_DIR%\config"
set "LIB_DIR=%SCRIPT_DIR%\lib"

REM Find Java
where java ^>nul 2^>^&1
if !errorlevel! neq 0 (
    echo [ERROR] Java not found. Please install JDK 21+ and add to PATH.
    exit /b 1
)

REM Build classpath
set "CLASSPATH=%LIB_DIR%"
for %%%%F in ^("%LIB_DIR%\*.jar"^) do (
    set "CLASSPATH=!CLASSPATH!;%%%%F"
)

REM Check input directory argument
if not "%~1"=="" set "INPUT_DIR=%~1"

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo ======================================================
echo ArkPrism Binary Privacy Analyzer
echo ======================================================
echo.
echo Input:     %INPUT_DIR%
echo Output:    %OUTPUT_DIR%
echo Config:    %CONFIG_DIR%
echo.

java -Xms4g -Xmx16g -Xss512m ^
    -cp "%CLASSPATH%" ^
    com.huawei.hisec.Main ^
    "%INPUT_DIR%" ^
    "%CONFIG_DIR%\privacy_apis.json" ^
    "%OUTPUT_DIR%" ^
    "%CONFIG_DIR%\profile_combinations.json" ^
    "%CONFIG_DIR%\native_privacy_apis.json"

echo.
echo Analysis complete.
pause
) > "%DIR%\run.bat"

exit /b 0

REM ============================================================
REM  Subroutine: Generate run.sh
REM ============================================================
:generate_run_sh
set "DIR=%~1"

(
echo #!/bin/bash
echo # ArkPrism - HarmonyOS Privacy API Analyzer
echo #
echo # Usage:
echo #   ./run.sh                     - Run with default input/ directory
echo #   ./run.sh ^<hap_dir^>           - Run with a single HAP directory
echo.
echo SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" ^&^& pwd)"
echo LIB_DIR="${SCRIPT_DIR}/lib"
echo CONFIG_DIR="${SCRIPT_DIR}/config"
echo INPUT_DIR="${SCRIPT_DIR}/input"
echo OUTPUT_DIR="${SCRIPT_DIR}/out"
echo.
echo # Build classpath
echo CLASSPATH=""
echo for jar in "${LIB_DIR}"/*.jar; do
echo     if [ -f "$jar" ]; then
echo         if [ -z "$CLASSPATH" ]; then
echo             CLASSPATH="$jar"
echo         else
echo             CLASSPATH="${CLASSPATH}:${jar}"
echo         fi
echo     fi
echo done
echo.
echo # Check input argument
echo if [ $# -gt 0 ]; then
echo     INPUT_DIR="$1"
echo fi
echo.
echo mkdir -p "$OUTPUT_DIR"
echo.
echo echo "======================================================"
echo echo "ArkPrism Binary Privacy Analyzer"
echo echo "======================================================"
echo echo "Input:     ${INPUT_DIR}"
echo echo "Output:    ${OUTPUT_DIR}"
echo echo "Config:    ${CONFIG_DIR}"
echo echo ""
echo.
echo java -Xms4g -Xmx16g -Xss512m \
echo     -cp "$CLASSPATH" \
echo     com.huawei.hisec.Main \
echo     "$INPUT_DIR" \
echo     "$CONFIG_DIR/privacy_apis.json" \
echo     "$OUTPUT_DIR" \
echo     "$CONFIG_DIR/profile_combinations.json" \
echo     "$CONFIG_DIR/native_privacy_apis.json"
) > "%DIR%\run.sh"

exit /b 0

REM ============================================================
REM  Subroutine: Generate SETUP.md
REM ============================================================
:generate_setup_doc
set "DIR=%~1"

(
echo # ArkPrism 部署配置指南
echo.
echo ## 目录结构
echo.
echo ```
echo ArkPrism-bin/
echo ├── run.bat              # Windows 启动脚本
echo ├── run.sh               # Linux/macOS 启动脚本
echo ├── SETUP.md             # 本文档
echo ├── config/
echo │   ├── privacy_apis.json           # ArkTS 敏感 API 规则
echo │   ├── native_privacy_apis.json    # Native C API 规则
echo │   └── profile_combinations.json   # 多源协作规则
echo ├── lib/
echo │   ├── arkprism-main.jar                              # 主程序
echo │   ├── hisec-enhance-app-analyzer-all-in-one-*.jar    # 华为 HiAnalyzer 分析引擎
echo │   ├── hisec-multi-language-*.jar                     # 多语言前端支持
echo │   ├── jackson-*.jar                                  # JSON 序列化
echo │   └── slf4j-*.jar                                    # 日志框架
echo ├── python_tools/
echo │   └── pure_angr_scanner.py    # Native SO 扫描器 (angr)
echo ├── input/                      # 放置待分析的 HAP 目录
echo └── out/                        # 分析结果输出
echo ```
echo.
echo ---
echo.
echo ## 环境要求
echo.
echo | 组件 | 版本要求 | 用途 |
echo |------|----------|------|
echo | JDK | 21+ | 运行主程序 |
echo | Python | 3.8+ | Native SO 分析 (仅 WSL/Linux) |
echo | angr | 9.2.124rc0+h1 | SO 二进制分析框架 |
echo | WSL | Ubuntu 22.04+ | Windows 下的 Linux 子系统 |
echo.
echo ---
echo.
echo ## 第一步：安装 Java 21
echo.
echo ### Windows
echo.
echo 1. 下载安装 [Microsoft JDK 21](https://learn.microsoft.com/zh-cn/java/openjdk/download) 或 [Adoptium JDK 21](https://adoptium.net/)
echo 2. 安装后确认：
echo    ```cmd
echo    java -version
echo    ```
echo    应显示 `openjdk version "21.x.x"`
echo.
echo ### Linux
echo.
echo ```bash
echo sudo apt install openjdk-21-jdk
echo java -version
echo ```
echo.
echo ---
echo.
echo ## 第二步：安装 WSL (仅 Windows)
echo.
echo WSL 用于运行 angr 进行 .so 文件分析。如果你不需要扫描 Native API，可以跳过此步。
echo.
echo ### 2.1 启用 WSL
echo.
echo 以管理员身份打开 PowerShell：
echo.
echo ```powershell
echo wsl --install -d Ubuntu-22.04
echo ```
echo.
echo 安装完成后需要重启电脑。重启后设置 Ubuntu 用户名和密码。
echo.
echo ### 2.2 验证 WSL
echo.
echo ```cmd
echo wsl -l -v
echo ```
echo.
echo 应看到 `Ubuntu-22.04` 状态为 Running。
echo.
echo ---
echo.
echo ## 第三步：安装 angr (在 WSL 中)
echo.
echo 打开 WSL 终端：
echo.
echo ```bash
echo wsl -d Ubuntu-22.04
echo ```
echo.
echo 在 WSL 内执行：
echo.
echo ```bash
echo # 更新系统
echo sudo apt update ^&^& sudo apt install -y python3 python3-pip
echo.
echo # 安装 angr (华为内部源)
echo # 方式一：从华为内部 PyPI 仓库安装
echo pip3 install angr-9.2.124rc0+h1.cbgcloud.appgallery.r14-py3-none-manylinux2014_x86_64.whl
echo.
echo # 方式二：如果华为内网可访问
echo pip3 install angr==9.2.124rc0+h1 -i https://cmc.centralrepo.rnd.huawei.com/artifactory/api/pypi/pypi-central-repo/simple
echo.
echo # 验证安装
echo python3 -c "import angr; print(angr.__version__)"
echo ```
echo.
echo **注意**：angr 是华为内部定制版本，不能使用公网 `pip install angr`。
echo.
echo ---
echo.
echo ## 第四步：部署 Python 扫描脚本
echo.
echo 将 `python_tools/pure_angr_scanner.py` 复制到 WSL 中：
echo.
echo ```bash
echo # 在 WSL 中执行
echo mkdir -p ~/arkprism
echo cp /mnt/d/path/to/ArkPrism-bin/python_tools/pure_angr_scanner.py ~/arkprism/
echo chmod +x ~/arkprism/pure_angr_scanner.py
echo ```
echo.
echo **默认路径**：Java 程序默认调用 `~/arkprism/pure_angr_scanner.py`。
echo 如果你放到其他路径，需要设置环境变量：
echo.
echo ```cmd
echo set ARKPRISM_WSL_SCANNER=/home/youruser/tools/pure_angr_scanner.py
echo ```
echo.
echo ---
echo.
echo ## 第五步：运行分析
echo.
echo ### 5.1 准备输入数据
echo.
echo 将 HAP 解包后的目录放入 `input/`：
echo.
echo ```
echo input/
echo ├── C6917602215994202990_1.0.0/    # 应用1
echo │   ├── ets/modules.abc            # ArkTS 字节码
echo │   ├── libs/arm64-v8a/*.so        # Native 库
echo │   └── module.json
echo └── C6917602221479724885_1.0.0/    # 应用2
echo     └── ...
echo ```
echo.
echo **HAP 解包方法**：
echo.
echo HarmonyOS 的 `.hap` 文件本质是 zip 包：
echo.
echo ```bash
echo mkdir -p C6917602215994202990_1.0.0
echo unzip app.hap -d C6917602215994202990_1.0.0
echo ```
echo.
echo ### 5.2 启动分析
echo.
echo **批量模式**（分析 input/ 下所有 HAP）：
echo.
echo ```cmd
echo run.bat
echo ```
echo.
echo **单应用模式**：
echo.
echo ```cmd
echo run.bat C:\path\to\hap_directory
echo ```
echo.
echo **自定义 JVM 内存**（大应用可能需要更多内存）：
echo.
echo 编辑 `run.bat`，修改：
echo ```batch
echo java -Xms8g -Xmx16g -Xss512m ...
echo ```
echo.
echo ### 5.3 查看结果
echo.
echo ```
echo out/
echo └── batch_20260706_100000/
echo     ├── C6917602215994202990_1.0.0/
echo     │   └── C6917602215994202990_1.0.0_privacy_report.json
echo     ├── arkprism_20260706_100000.log
echo     └── batch_summary.json
echo ```
echo.
echo ---
echo.
echo ## 环境变量参考
echo.
echo | 变量名 | 默认值 | 说明 |
echo |--------|--------|------|
echo | `ARKPRISM_WSL_PYTHON` | `python3` | WSL 中 Python 可执行文件路径 |
echo | `ARKPRISM_WSL_SCANNER` | `~/arkprism/pure_angr_scanner.py` | WSL 中扫描脚本路径 |
echo.
echo 使用示例：
echo.
echo ```cmd
echo set ARKPRISM_WSL_PYTHON=/home/user/.venv/bin/python3
echo set ARKPRISM_WSL_SCANNER=/home/user/tools/pure_angr_scanner.py
echo run.bat
echo ```
echo.
echo ---
echo.
echo ## Linux 环境运行
echo.
echo 在 Linux 上不需要 WSL，angr 直接运行：
echo.
echo ```bash
echo # 安装依赖
echo sudo apt install openjdk-21-jdk python3-pip
echo pip3 install angr-9.2.124rc0+h1.cbgcloud.appgallery.r14-py3-none-manylinux2014_x86_64.whl
echo.
echo # 部署扫描脚本
echo mkdir -p ~/arkprism
echo cp python_tools/pure_angr_scanner.py ~/arkprism/
echo.
echo # 运行
echo chmod +x run.sh
echo ./run.sh /path/to/hap_directory
echo ```
echo.
echo **注意**：Linux 下需要修改 `SoVulnerabilityScanner.java` 中的调用方式，
echo 将 `wsl.exe -d Ubuntu-22.04 --` 改为直接调用 `python3`。
echo 或设置环境变量让程序检测 Linux 环境。
echo.
echo ---
echo.
echo ## 常见问题
echo.
echo ### Q: OutOfMemoryError
echo.
echo 增大 JVM 堆内存，编辑 `run.bat`：
echo ```batch
echo java -Xms8g -Xmx16g -Xss512m ...
echo ```
echo.
echo ### Q: Native SO 分析报错 / exitCode=2
echo.
echo 1. 检查 WSL 是否正常：`wsl -l -v`
echo 2. 检查 angr 是否安装：`wsl python3 -c "import angr; print(angr.__version__)"`
echo 3. 检查扫描脚本路径：确认 `~/arkprism/pure_angr_scanner.py` 存在
echo 4. 如果不需要 Native 分析，可以忽略此错误（只影响 .so 扫描）
echo.
echo ### Q: IFDS 求解报 NullPointerException
echo.
echo 这是 HiAnalyzer 引擎的已知问题（`HiFunction.getBody()` 返回 null），
echo 不影响其他分析结果。ArkTS API 检测和调用链构建不受影响。
echo.
echo ### Q: 找不到 HAP 目录
echo.
echo 确保输入目录下有包含 `.abc` 或 `.so` 文件的子目录。
echo 如果 HAP 还未解包，先用 `unzip` 解压 `.hap` 文件。
echo.
echo ### Q: 如何更新敏感 API 规则
echo.
echo 替换 `config/` 下的 JSON 文件即可：
echo - `privacy_apis.json` — ArkTS 敏感 API 定义
echo - `native_privacy_apis.json` — Native C API 定义
echo - `profile_combinations.json` — 多源协作规则
echo.
echo 规则格式说明见文件内注释或项目文档。
) > "%DIR%\SETUP.md"

exit /b 0
