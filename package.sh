#!/bin/bash
# ============================================================
#  ArkPrism Binary Analyzer - Package Script
#  Builds a self-contained distribution for deployment.
#
#  Usage:
#    bash package.sh              # Default output: dist/ArkPrism-bin
#    bash package.sh /path/to/out # Custom output directory
# ============================================================

set -eo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${1:-$PROJECT_DIR/dist/ArkPrism-bin}"

echo "======================================================"
echo " ArkPrism Package Builder"
echo "======================================================"
echo " Project:  $PROJECT_DIR"
echo " Output:   $OUTPUT_DIR"
echo ""

# ---- 1. Directory structure ----
echo "[1/6] Creating directory structure..."
mkdir -p "$OUTPUT_DIR"/{lib,config,python_tools,input}

# ---- 2. Check compiled classes ----
echo "[2/6] Checking compiled classes..."
if [ ! -f "$PROJECT_DIR/target/classes/com/huawei/hisec/Main.class" ]; then
    echo "  [ERROR] No compiled classes found. Compile in IDEA first."
    exit 1
fi
echo "  Found compiled classes."

# ---- 3. Build main JAR ----
echo "[3/6] Building ArkPrism main JAR..."
MAIN_JAR="$OUTPUT_DIR/lib/arkprism-main.jar"
cd "$PROJECT_DIR/target/classes"
jar cf "$MAIN_JAR" com/
echo "  Created: $MAIN_JAR"

# ---- 4. Copy dependency JARs ----
echo "[4/6] Copying dependency JARs..."
DEP_COUNT=0
for src_dir in "$PROJECT_DIR/lib" "$PROJECT_DIR/dist/ArkPrism-bin/lib"; do
    if [ -d "$src_dir" ]; then
        for jar in "$src_dir"/*.jar; do
            [ -f "$jar" ] || continue
            basename=$(basename "$jar")
            # Skip if already copied (e.g. arkprism-main.jar we just built)
            [ -f "$OUTPUT_DIR/lib/$basename" ] && continue
            cp -f "$jar" "$OUTPUT_DIR/lib/"
            DEP_COUNT=$((DEP_COUNT + 1))
        done
    fi
done
echo "  Copied $DEP_COUNT JAR files."

# ---- 5. Copy config files ----
echo "[5/6] Copying config files..."
for f in privacy_apis.json native_privacy_apis.json profile_combinations.json; do
    if [ -f "$PROJECT_DIR/config/$f" ]; then
        cp -f "$PROJECT_DIR/config/$f" "$OUTPUT_DIR/config/"
    fi
done
echo "  Config files synced."

# ---- 6. Copy Python tools and generate scripts ----
echo "[6/6] Copying Python tools and generating scripts..."

# Python scanner
SCANNER_SRC=""
for candidate in \
    "$PROJECT_DIR/src/main/python/pure_angr_scanner.py" \
    "$PROJECT_DIR/dist/ArkPrism-bin/python_tools/pure_angr_scanner.py"; do
    if [ -f "$candidate" ]; then
        SCANNER_SRC="$candidate"
        break
    fi
done
if [ -n "$SCANNER_SRC" ]; then
    cp -nf "$SCANNER_SRC" "$OUTPUT_DIR/python_tools/" 2>/dev/null || true
    echo "  Copied pure_angr_scanner.py"
else
    echo "  [WARN] pure_angr_scanner.py not found"
fi

# Generate run.bat
cat > "$OUTPUT_DIR/run.bat" << 'RUNBAT'
@echo off
REM ArkPrism - HarmonyOS Privacy API Analyzer
REM
REM Usage:
REM   run.bat                     - Run with default input/ directory (batch mode)
REM   run.bat <hap_dir>           - Run with a single HAP directory

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

set "INPUT_DIR=%SCRIPT_DIR%\input"
set "OUTPUT_DIR=%SCRIPT_DIR%\out"
set "CONFIG_DIR=%SCRIPT_DIR%\config"
set "LIB_DIR=%SCRIPT_DIR%\lib"

where java >nul 2>&1
if !errorlevel! neq 0 (
    echo [ERROR] Java not found. Please install JDK 21+ and add to PATH.
    exit /b 1
)

set "CLASSPATH=%LIB_DIR%"
for %%F in ("%LIB_DIR%\*.jar") do (
    set "CLASSPATH=!CLASSPATH!;%%F"
)

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

java -Xms4g -Xmx8g -Xss512m ^
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
RUNBAT

# Generate run.sh
cat > "$OUTPUT_DIR/run.sh" << 'RUNSH'
#!/bin/bash
# ArkPrism - HarmonyOS Privacy API Analyzer
#
# Usage:
#   ./run.sh                     - Run with default input/ directory
#   ./run.sh <hap_dir>           - Run with a single HAP directory

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
CONFIG_DIR="${SCRIPT_DIR}/config"
INPUT_DIR="${SCRIPT_DIR}/input"
OUTPUT_DIR="${SCRIPT_DIR}/out"

CLASSPATH=""
for jar in "${LIB_DIR}"/*.jar; do
    if [ -f "$jar" ]; then
        if [ -z "$CLASSPATH" ]; then
            CLASSPATH="$jar"
        else
            CLASSPATH="${CLASSPATH}:${jar}"
        fi
    fi
done

if [ $# -gt 0 ]; then
    INPUT_DIR="$1"
fi

mkdir -p "$OUTPUT_DIR"

echo "======================================================"
echo "ArkPrism Binary Privacy Analyzer"
echo "======================================================"
echo "Input:     ${INPUT_DIR}"
echo "Output:    ${OUTPUT_DIR}"
echo "Config:    ${CONFIG_DIR}"
echo ""

java -Xms4g -Xmx8g -Xss512m \
    -cp "$CLASSPATH" \
    com.huawei.hisec.Main \
    "$INPUT_DIR" \
    "$CONFIG_DIR/privacy_apis.json" \
    "$OUTPUT_DIR" \
    "$CONFIG_DIR/profile_combinations.json" \
    "$CONFIG_DIR/native_privacy_apis.json"

echo ""
echo "Analysis complete."
RUNSH
chmod +x "$OUTPUT_DIR/run.sh"

echo ""
echo "======================================================"
echo " Package built successfully!"
echo " Output: $OUTPUT_DIR"
echo "======================================================"
echo ""
echo " Next steps:"
echo "   1. Copy $OUTPUT_DIR to target machine"
echo "   2. Follow SETUP.md for environment setup"
echo "   3. Place HAP directories in input/"
echo "   4. Run: run.bat"
echo ""
