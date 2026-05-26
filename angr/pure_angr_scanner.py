import sys
import json
import os
import logging
import traceback
from typing import Dict, Any, List, Tuple, Optional


DEBUG_DUMP_IMPORTS = False
DEFAULT_RULE_FILE = "native_privacy_apis.json"

# Common C library / system symbols that are NOT privacy-sensitive.
# Excluded to avoid false positives from generic dynamic loading / process control APIs.
SYSTEM_LIB_SYMBOLS_TO_SKIP = frozenset({
    "dlopen", "dlsym", "dlclose", "dlerror", "dladdr", "dladdr",
    "system", "popen", "pclose", "execve", "fork", "vfork",
    "pthread_create", "pthread_join", "pthread_exit",
    "malloc", "calloc", "realloc", "free",
    "memcpy", "memmove", "memset", "memcmp", "memchr",
    "strlen", "strcpy", "strncpy", "strcmp", "strncmp", "strcat", "strncat",
    "strchr", "strrchr", "strstr", "strtok", "strdup", "strndup",
    "sprintf", "snprintf", "sscanf", "vsprintf", "vsnprintf",
    "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull",
    "open", "close", "read", "write", "lseek", "stat", "fstat",
    "printf", "fprintf", "sprintf", "vprintf", "vfprintf", "vsprintf",
    "exit", "_exit", "abort", "assert",
    "fopen", "fclose", "fread", "fwrite", "fgets", "fputs",
    "getenv", "setenv", "unsetenv",
    "time", "localtime", "gmtime", "mktime", "strftime",
    "rand", "srand", "random",
    "signal", "raise",
    "cos", "sin", "tan", "acos", "asin", "atan", "atan2",
    "sqrt", "pow", "exp", "log", "log10", "floor", "ceil", "fabs",
    "__cxa_atexit", "__cxa_finalize",
    "J EMCC",  # Emscripten
})


# ==========================================================
# 强制保证 stdout 只输出最终 JSON
# 任何第三方库 / angr 的杂乱输出都重定向到 stderr
# ==========================================================

_REAL_STDOUT = sys.stdout
sys.stdout = sys.stderr


try:
    import angr
except Exception as import_error:
    print(json.dumps([], ensure_ascii=False), file=_REAL_STDOUT, flush=True)
    print(f"[-] failed to import angr: {import_error}", file=sys.stderr, flush=True)
    sys.exit(2)


# ==========================================================
# 日志
# ==========================================================

for logger_name in ["angr", "cle", "pyvex", "claripy"]:
    logging.getLogger(logger_name).setLevel(logging.CRITICAL)

logging.disable(logging.CRITICAL)


def log(msg: str):
    print(msg, file=sys.stderr, flush=True)


# ==========================================================
# Native API 规则读取
# ==========================================================

def load_native_rules(rule_path: str) -> Dict[str, Dict[str, Any]]:
    """
    读取 native_privacy_apis.json。

    期望结构：
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
    """
    if not rule_path:
        rule_path = DEFAULT_RULE_FILE

    if not os.path.exists(rule_path):
        log(f"[-] native rule file not found: {rule_path}")
        return {}

    try:
        with open(rule_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        native_apis = data.get("nativeApis", [])
        if not isinstance(native_apis, list):
            log("[-] invalid native rule file: nativeApis must be a list")
            return {}

        rules: Dict[str, Dict[str, Any]] = {}

        for item in native_apis:
            if not isinstance(item, dict):
                continue

            symbol = str(item.get("symbol", "")).strip()
            if not symbol:
                continue

            match_modes = item.get("matchModes")
            if not isinstance(match_modes, list) or not match_modes:
                match_modes = ["import_symbol", "string_reference"]

            rules[symbol] = {
                "symbol": symbol,
                "prototype": item.get("prototype", ""),
                "category": item.get("category", "unknown"),
                "profilingCategory": item.get("profilingCategory", "unknown"),
                "apiPackage": item.get("apiPackage", ""),
                "matchModes": set(
                    str(x).strip()
                    for x in match_modes
                    if str(x).strip()
                )
            }

        log(f"[*] native rules loaded: {len(rules)} from {rule_path}")
        return rules

    except Exception as e:
        log(f"[-] failed to load native rules: {e}")
        log(traceback.format_exc())
        return {}


# ==========================================================
# 基础工具
# ==========================================================

def clean_symbol_name(name: str) -> str:
    if not name:
        return ""

    # 去掉版本后缀，例如 symbol@GLIBC_xxx
    name = name.split("@")[0]

    return name.strip()


def safe_hex(value):
    if value is None:
        return None

    try:
        return hex(value)
    except Exception:
        return None


def normalize_arch(project) -> str:
    try:
        return str(project.arch)
    except Exception:
        return "unknown"


def has_match_mode(rule: Dict[str, Any], mode: str) -> bool:
    modes = rule.get("matchModes", set())
    return mode in modes


def is_symbol_boundary(byte_value: Optional[int]) -> bool:
    """
    判断字符串边界。
    避免把 OH_GetDeviceType 匹配到 XXOH_GetDeviceTypeYY 这种长 token 里。
    """
    if byte_value is None:
        return True

    # [a-zA-Z0-9_]
    if 65 <= byte_value <= 90:
        return False
    if 97 <= byte_value <= 122:
        return False
    if 48 <= byte_value <= 57:
        return False
    if byte_value == 95:
        return False

    return True


def find_whole_token(blob: bytes, needle: bytes) -> int:
    """
    在 blob 中查找完整 token。
    只返回第一个命中位置。
    """
    start = 0

    while True:
        pos = blob.find(needle, start)
        if pos < 0:
            return -1

        before = blob[pos - 1] if pos > 0 else None
        after_pos = pos + len(needle)
        after = blob[after_pos] if after_pos < len(blob) else None

        if is_symbol_boundary(before) and is_symbol_boundary(after):
            return pos

        start = pos + 1


def iter_readable_blobs(main_obj) -> List[Tuple[int, bytes, str]]:
    """
    读取可扫描 section，优先避免直接读取整个 [min_addr, max_addr]。

    返回：
      [(base_addr, blob, section_name), ...]
    """
    blobs: List[Tuple[int, bytes, str]] = []

    try:
        sections = list(main_obj.sections)
    except Exception:
        sections = []

    for sec in sections:
        try:
            name = getattr(sec, "name", "") or ""
            vaddr = getattr(sec, "vaddr", None)
            memsize = getattr(sec, "memsize", 0)

            if vaddr is None or not memsize or memsize <= 0:
                continue

            lower_name = name.lower()

            # 排除 debug 节（DWARF 调试信息包含大量符号名字符串，非运行时引用）
            if lower_name.startswith(".debug"):
                continue

            # 主要扫描字符串、只读数据、数据区。
            # 移除 .strtab（字符串表含大量无关字符串，误报率高）
            # 移除 .text（代码段嵌入的符号名不可靠）
            if lower_name and not any(k in lower_name for k in [
                ".rodata", ".data", ".dynstr"
            ]):
                continue

            blob = main_obj.memory.load(vaddr, memsize)
            if blob:
                blobs.append((vaddr, blob, name))

        except Exception:
            continue

    if blobs:
        return blobs

    # fallback：读取整个对象内存范围
    try:
        min_addr = main_obj.min_addr
        max_addr = main_obj.max_addr
        blob = main_obj.memory.load(min_addr, max_addr - min_addr)
        return [(min_addr, blob, "whole_object")]
    except Exception:
        return []


# ==========================================================
# Import Symbol 匹配
# ==========================================================

def analyze_import_symbols(project, so_path: str, rules: Dict[str, Dict[str, Any]]):
    """
    强证据：
    解析 ELF 导入表，若导入符号名与规则 symbol 精确相等，则命中。
    """
    results = []
    main_obj = project.loader.main_object
    imports = main_obj.imports

    log(f"[*] imports={len(imports)}")

    if DEBUG_DUMP_IMPORTS:
        log("[*] import symbols:")
        for raw_name in sorted(imports.keys()):
            log(f"    IMPORT: {raw_name}")

    for raw_name, reloc in imports.items():
        clean_name = clean_symbol_name(raw_name)

        if clean_name in SYSTEM_LIB_SYMBOLS_TO_SKIP:
            continue

        rule = rules.get(clean_name)
        if not rule:
            continue

        if not has_match_mode(rule, "import_symbol"):
            continue

        reloc_addr = getattr(reloc, "rebased_addr", None)
        resolved = getattr(reloc, "resolvedby", None)
        resolved_addr = getattr(resolved, "rebased_addr", None) if resolved else None

        results.append({
            "so": os.path.basename(so_path),
            "so_path": so_path,
            "arch": normalize_arch(project),

            "method": clean_name,
            "symbol": raw_name,
            "prototype": rule.get("prototype", ""),
            "category": rule.get("category", "unknown"),
            "profilingCategory": rule.get("profilingCategory", "unknown"),
            "apiPackage": rule.get("apiPackage", ""),

            "match_type": "import_symbol",
            "confidence": "high",

            "evidence": {
                "reloc_addr": safe_hex(reloc_addr),
                "resolved_addr": safe_hex(resolved_addr)
            }
        })

    return results


# ==========================================================
# String Reference 匹配
# ==========================================================

def analyze_string_references(
        project,
        so_path: str,
        rules: Dict[str, Dict[str, Any]],
        already_hit_methods: set
):
    """
    补充证据：
    扫描 SO 字符串区，如果出现敏感 API 名字符串，则输出 string_reference。

    注意：
    string_reference 只证明符号名字符串出现；
    不等价于已经确认发生 dlsym 调用。
    """
    results = []
    main_obj = project.loader.main_object

    imports = main_obj.imports
    imported_names = {clean_symbol_name(x) for x in imports.keys()}

    has_dynamic_resolver = "dlsym" in imported_names or "dlopen" in imported_names

    blobs = iter_readable_blobs(main_obj)
    if not blobs:
        return results

    for api_name, rule in rules.items():
        if api_name in already_hit_methods:
            continue

        if api_name in SYSTEM_LIB_SYMBOLS_TO_SKIP:
            continue
            continue

        if not has_match_mode(rule, "string_reference"):
            continue

        needle = api_name.encode("utf-8")

        for base_addr, blob, section_name in blobs:
            offset = find_whole_token(blob, needle)
            if offset < 0:
                continue

            confidence = "medium" if has_dynamic_resolver else "low"

            results.append({
                "so": os.path.basename(so_path),
                "so_path": so_path,
                "arch": normalize_arch(project),

                "method": api_name,
                "symbol": api_name,
                "prototype": rule.get("prototype", ""),
                "category": rule.get("category", "unknown"),
                "profilingCategory": rule.get("profilingCategory", "unknown"),
                "apiPackage": rule.get("apiPackage", ""),

                "match_type": "string_reference",
                "confidence": confidence,

                "evidence": {
                    "string_addr": safe_hex(base_addr + offset),
                    "section": section_name,
                    "dynamic_resolver_imported": has_dynamic_resolver
                }
            })

            break

    return results


# ==========================================================
# SO 分析主流程
# ==========================================================

def analyze_so(so_path: str, rule_path: str):
    log(f"[*] preparing={so_path}")

    rules = load_native_rules(rule_path)
    if not rules:
        log("[!] no native rules loaded; return empty result")
        return []

    project = angr.Project(
        so_path,
        load_options={"auto_load_libs": False}
    )

    log(f"[*] loaded={so_path}")
    log(f"[*] arch={normalize_arch(project)}")

    import_hits = analyze_import_symbols(project, so_path, rules)
    already_hit_methods = {item["method"] for item in import_hits}

    string_hits = analyze_string_references(
        project,
        so_path,
        rules,
        already_hit_methods
    )

    results = import_hits + string_hits

    log(f"[*] hits={len(results)}")
    return results


def main():
    if len(sys.argv) < 2:
        print(json.dumps([], ensure_ascii=False), file=_REAL_STDOUT, flush=True)
        log("[-] missing so path")
        sys.exit(1)

    so_path = sys.argv[1]
    rule_path = sys.argv[2] if len(sys.argv) >= 3 else DEFAULT_RULE_FILE

    try:
        results = analyze_so(so_path, rule_path)
        print(json.dumps(results, ensure_ascii=False), file=_REAL_STDOUT, flush=True)

    except Exception as e:
        log(f"[-] engine error: {e}")
        log(traceback.format_exc())

        print(json.dumps([], ensure_ascii=False), file=_REAL_STDOUT, flush=True)
        sys.exit(2)


if __name__ == "__main__":
    main()