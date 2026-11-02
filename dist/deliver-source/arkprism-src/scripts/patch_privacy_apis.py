#!/usr/bin/env python3
"""
Patch privacy_apis.json to add explicit dataDirection field to each API rule.

Architecture follows top-tier conference practices (FlowDroid, Amandroid):
- Each API has an explicit dataDirection: "source" | "sink" | "both" | "excluded"
- dataDirection takes precedence over profilingCategory inference
- No more implicit string matching to determine direction
"""

import json
import sys
import os
from pathlib import Path

# ==========================================================
# Direction classification by profilingCategory
# ==========================================================

# Explicit direction overrides (method-level)
# Format: (namespace, method) -> "source" | "sink" | "both" | "excluded"
METHOD_DIRECTION_OVERRIDES = {
    # user_preference.settings: getValue=read, setValue=write
    ("settings", "getValueSync"): "source",
    ("settings", "getValue"): "source",
    ("settings", "setValue"): "sink",
}


def classify_by_profilingcategory(profiling_category: str) -> str | None:
    """
    Classify direction purely from profilingCategory.
    Only used as fallback when rule has no explicit dataDirection.
    Returns: "source" | "sink" | "both" | "excluded" | None
    """
    if profiling_category is None:
        return None

    lower = profiling_category.lower()

    # EXCLUDED: non-personally-identifying hardware/UI info
    if lower in (
        "device_identity.screen",
        "device_status.battery",
        "device_status.uptime",
        "device_status.vibrator",
    ):
        return "excluded"

    # SOURCE: reading privacy-sensitive data
    if (
        lower == "location"
        or lower.startswith("device_identity.")
        or lower.startswith("device_status.")
        or lower.startswith("media.")
        or lower.startswith("user_data.")
        or lower.startswith("user_behavior.")
        or lower.startswith("user_preference.")
        or lower.startswith("user_interaction.")
        or lower == "app_environment"
        or lower.startswith("app_environment.")
    ):
        return "source"

    # SINK: sending/exfiltrating data or writing to storage
    if (
        lower.startswith("network.")
        or lower.startswith("data_storage.")
        or lower == "app_analytics"
        or lower.startswith("app_analytics.")
        or lower == "app_behavior"
        or lower.startswith("app_behavior.")
    ):
        return "sink"

    return None


def patch_api_rule(rule: dict) -> dict:
    """
    Add dataDirection to a single API rule.
    Priority:
    1. METHOD_DIRECTION_OVERRIDES (explicit per-method override)
    2. Existing rule.dataDirection (already set by user)
    3. Fallback: infer from profilingCategory
    """
    namespace = rule.get("namespace", "")
    method = rule.get("method", "")
    profiling_category = rule.get("profilingCategory")

    # Check method-level override first
    override = METHOD_DIRECTION_OVERRIDES.get((namespace, method))
    if override:
        rule["dataDirection"] = override
        return rule

    # Use existing dataDirection if already set
    if rule.get("dataDirection"):
        return rule

    # Fallback: infer from profilingCategory
    inferred = classify_by_profilingcategory(profiling_category)
    if inferred:
        rule["dataDirection"] = inferred

    return rule


def patch_file(input_path: str, output_path: str = None):
    if output_path is None:
        output_path = input_path

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    total_apis = 0
    direction_counts = {"source": 0, "sink": 0, "both": 0, "excluded": 0, "unresolved": 0}

    for pkg in data:
        apis = pkg.get("privacyApis", [])
        for rule in apis:
            total_apis += 1
            patched = patch_api_rule(rule)
            direction = patched.get("dataDirection", None)
            if direction in direction_counts:
                direction_counts[direction] += 1
            else:
                direction_counts["unresolved"] += 1

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

    print(f"[*] Patched {total_apis} API rules:")
    for d, c in direction_counts.items():
        print(f"    {d}: {c}")
    print(f"[+] Written to {output_path}")


if __name__ == "__main__":
    script_dir = Path(__file__).parent
    input_json = script_dir.parent / "privacy_apis.json"

    if not input_json.exists():
        print(f"[-] File not found: {input_json}")
        sys.exit(1)

    # Backup original
    backup_path = input_json.with_suffix(".json.bak")
    if not backup_path.exists():
        import shutil

        shutil.copy2(input_json, backup_path)
        print(f"[*] Backup created: {backup_path}")

    patch_file(str(input_json))