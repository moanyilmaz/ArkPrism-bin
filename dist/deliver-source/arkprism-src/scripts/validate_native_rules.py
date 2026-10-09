#!/usr/bin/env python3
"""
Validate native_privacy_apis.json rules against real OpenHarmony system libraries.

Usage:
    python scripts/validate_native_rules.py /path/to/ohos/libs

This script:
1. Loads rules from native_privacy_apis.json
2. Scans .so files for exported OH_* symbols
3. Reports which rules have matches in real system libraries
4. Reports unknown/unmatched rules
"""

import json
import sys
import os
from pathlib import Path
from collections import defaultdict

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("[-] pyelftools not installed. Run: pip install pyelftools")
    sys.exit(1)


def extract_exported_symbols(so_path: str) -> set:
    """Extract exported function symbols from a .so file."""
    symbols = set()
    try:
        with open(so_path, 'rb') as f:
            ef = ELFFile(f)
            dynsym = ef.get_section_by_name('.dynsym')
            dynstr = ef.get_section_by_name('.dynstr')

            if dynsym and dynstr:
                for sym in dynsym.iter_symbols():
                    bind = sym['st_info']['bind']
                    stype = sym['st_info']['type']
                    name = dynstr.get_string(sym['st_name'])

                    # Only consider globally visible function symbols
                    if (name and
                        bind in ('STB_GLOBAL', 'STB_WEAK') and
                        stype == 'STT_FUNC'):
                        symbols.add(name)
    except Exception as e:
        pass
    return symbols


def scan_directory(libs_dir: str) -> dict:
    """
    Scan all .so files in directory for exported OH_* symbols.
    Returns: {symbol_name: [(so_file, so_path), ...]}
    """
    symbol_to_files = defaultdict(list)

    for root, dirs, files in os.walk(libs_dir):
        for fname in files:
            if not fname.endswith('.so'):
                continue
            so_path = os.path.join(root, fname)
            symbols = extract_exported_symbols(so_path)

            for sym in symbols:
                if sym.startswith('OH_'):
                    symbol_to_files[sym].append((fname, so_path))

    return symbol_to_files


def main():
    if len(sys.argv) < 2:
        print("Usage: python validate_native_rules.py /path/to/ohos/libs")
        print()
        print("Example: python validate_native_rules.py /usr/lib/arm-linux-gnueabihf/")
        sys.exit(1)

    libs_dir = sys.argv[1]
    if not os.path.isdir(libs_dir):
        print(f"[-] Directory not found: {libs_dir}")
        sys.exit(1)

    # Load rules
    script_dir = Path(__file__).parent.parent
    rules_file = script_dir / "native_privacy_apis.json"

    with open(rules_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    rules_by_symbol = {entry['symbol']: entry for entry in data['nativeApis']}
    print(f"[*] Loaded {len(rules_by_symbol)} rules from {rules_file}")

    # Scan libs directory
    print(f"[*] Scanning: {libs_dir}")
    symbol_to_files = scan_directory(libs_dir)
    print(f"[*] Found {len(symbol_to_files)} unique OH_* exported symbols")

    # Match rules against real symbols
    matched = {}
    unmatched = {}

    for sym, entry in rules_by_symbol.items():
        if sym in symbol_to_files:
            matched[sym] = (entry, symbol_to_files[sym])
        else:
            unmatched[sym] = entry

    print(f"\n[*] Validation Results:")
    print(f"    Matched (in real system libs): {len(matched)}")
    print(f"    Unmatched (not found in scanned libs): {len(unmatched)}")

    if matched:
        print(f"\n[*] Top matched symbols:")
        for sym, (entry, locations) in sorted(matched.items())[:20]:
            locs_str = ', '.join([f[0] for f in locations[:2]])
            print(f"    ✓ {sym} ({entry['category']}) in {locs_str}")

    if unmatched:
        # Group by category for analysis
        by_category = defaultdict(list)
        for sym, entry in unmatched.items():
            by_category[entry.get('category', 'unknown')].append(sym)

        print(f"\n[*] Unmatched symbols by category:")
        for cat, syms in sorted(by_category.items(), key=lambda x: -len(x[1])):
            print(f"    {cat}: {len(syms)} symbols")
            for s in sorted(syms)[:5]:
                print(f"        - {s}")
            if len(syms) > 5:
                print(f"        ... and {len(syms) - 5} more")

    # Save unmatched rules for further analysis
    output_file = script_dir / "out" / "unmatched_native_rules.json"
    output_file.parent.mkdir(exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump([
            {"symbol": sym, **entry}
            for sym, entry in sorted(unmatched.items())
        ], f, ensure_ascii=False, indent=2)
    print(f"\n[*] Unmatched rules saved to: {output_file}")


if __name__ == "__main__":
    main()