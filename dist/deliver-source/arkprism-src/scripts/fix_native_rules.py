#!/usr/bin/env python3
"""
Fix native_privacy_apis.json:
1. Add dataDirection to all entries (infer from profilingCategory)
2. Fix OH_Media_Create duplicate (createAudioRecorder vs createVideoRecorder)
3. Clean up dlopen/dlsym/system/popen (they're already excluded in Python scanner,
   but should not appear in privacy reports)
"""

import json
import sys
import os
from pathlib import Path

# ==========================================================
# profilingCategory → dataDirection mapping
# ==========================================================
PROFILING_TO_DIRECTION = {
    # SOURCE
    "location": "source",
    "device_identity.ad_tracking": "source",
    "device_identity.sim": "source",
    "device_identity.hardware": "source",
    "device_identity.software": "source",
    "device_identity.unique_id": "source",
    "device_identity.mac": "source",
    "device_identity.distributed": "source",
    "device_identity.screen": "excluded",
    "device_status.battery": "excluded",
    "device_status.uptime": "excluded",
    "device_status.vibrator": "excluded",
    "device_status.sensor": "source",
    "media.camera": "source",
    "media.audio": "source",
    "media.recording": "source",
    "user_data.contacts": "source",
    "user_data.sms": "source",
    "user_data.calendar": "source",
    "user_data.clipboard": "source",
    "user_data.account": "source",
    "user_data.media": "source",
    "user_data.cookie": "source",
    "user_data.file_picker": "source",
    "user_preference.locale": "source",
    "user_preference.settings": "source",  # getValue=source, setValue=sink — handled below
    "user_preference.time": "source",
    "user_preference.input": "source",
    "user_behavior.call": "source",
    "user_interaction.notification": "source",
    "app_environment": "source",
    "app_environment.installed_apps": "source",
    "app_environment.permissions": "source",
    # SINK
    "network.cellular": "sink",
    "network.wifi": "sink",
    "network.bluetooth": "sink",
    "network.http": "sink",
    "network.socket": "sink",
    "network.webview": "sink",
    "network.upload": "sink",
    "network.download": "sink",
    "network.connectivity": "sink",
    "data_storage.preferences": "sink",
    "data_storage.database": "sink",
    "data_storage.distributed": "sink",
    "data_storage.filesystem": "sink",
    "app_analytics": "sink",
    "app_behavior.background": "sink",
}

# Symbol renaming for duplicates
SYMBOL_RENAME = {
    # createAudioRecorder → OH_AudioRecorder_Create
    ("OH_Media_Create", "createAudioRecorder"): "OH_AudioRecorder_Create",
    # createVideoRecorder → OH_VideoRecorder_Create
    ("OH_Media_Create", "createVideoRecorder"): "OH_VideoRecorder_Create",
}


def infer_direction(profiling_category: str) -> str | None:
    return PROFILING_TO_DIRECTION.get(profiling_category)


def main():
    script_dir = Path(__file__).parent
    native_json = script_dir.parent / "native_privacy_apis.json"

    with open(native_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Build symbol → [entries] map to find duplicates
    symbol_entries = {}
    for entry in data["nativeApis"]:
        sym = entry["symbol"]
        if sym not in symbol_entries:
            symbol_entries[sym] = []
        symbol_entries[sym].append(entry)

    fixed_symbols = set()
    for sym, entries in symbol_entries.items():
        if len(entries) > 1:
            fixed_symbols.add(sym)
            print(f"[*] Fixing duplicate: {sym}")
            for entry in entries:
                # Rename duplicates
                old_sym = entry["symbol"]
                # Find namespace.method from the symbol
                ns_method = None
                for ns, meth in SYMBOL_RENAME:
                    if SYMBOL_RENAME[(ns, meth)] == sym:
                        ns_method = meth
                        break

                # Try to determine rename based on category
                pc = entry.get("profilingCategory", "")
                if "recording" in pc or "Audio" in entry.get("category", ""):
                    new_sym = "OH_AudioRecorder_Create"
                elif "video" in pc.lower() or "Video" in entry.get("category", ""):
                    new_sym = "OH_VideoRecorder_Create"
                else:
                    new_sym = f"{sym}_{len(entries)}"  # fallback

                if new_sym != old_sym:
                    print(f"    {old_sym} → {new_sym}")
                    entry["symbol"] = new_sym
                    entry["prototype"] = f"unknown {new_sym}(...)"

    # Now add dataDirection to all entries and fix settings method-level
    no_direction = 0
    settings_getvalue_count = 0
    for entry in data["nativeApis"]:
        pc = entry.get("profilingCategory", "")
        sym = entry["symbol"]

        # Method-level override for settings
        if sym in ("OH_Settings_GetValueSync", "OH_Settings_GetValue"):
            entry["dataDirection"] = "source"
            settings_getvalue_count += 1
            continue
        elif sym == "OH_Settings_SetValue":
            entry["dataDirection"] = "sink"
            settings_getvalue_count += 1
            continue

        direction = infer_direction(pc)
        if direction:
            entry["dataDirection"] = direction
        else:
            no_direction += 1

    print(f"\n[*] Settings method-level override: {settings_getvalue_count}")
    print(f"[*] Entries without dataDirection: {no_direction}")

    # Remove dlopen/dlsym/system/popen — they're noise, not privacy APIs
    # (the Python scanner already skips them, but they should not be in the rule file)
    noise_symbols = {"dlopen", "dlsym", "system", "popen"}
    removed = [e for e in data["nativeApis"] if e["symbol"] in noise_symbols]
    data["nativeApis"] = [e for e in data["nativeApis"] if e["symbol"] not in noise_symbols]
    if removed:
        print(f"\n[*] Removed noise symbols: {[e['symbol'] for e in removed]}")

    # Summary
    total = len(data["nativeApis"])
    from collections import Counter
    dd_counts = Counter(e.get("dataDirection", "MISSING") for e in data["nativeApis"])
    pc_counts = Counter(e["profilingCategory"] for e in data["nativeApis"])
    print(f"\n[*] Final native API count: {total}")
    print(f"    dataDirection: {dict(dd_counts)}")
    print(f"    profilingCategory coverage: {len(pc_counts)} categories")
    print(f"    Duplicates fixed: {len(fixed_symbols)}")

    with open(native_json, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[+] Written to {native_json}")


if __name__ == "__main__":
    main()