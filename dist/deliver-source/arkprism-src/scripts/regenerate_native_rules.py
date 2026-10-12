#!/usr/bin/env python3
"""
Regenerate native_privacy_apis.json from real SO files using pyelftools.

This script:
1. Scans all .so files in a directory for OH_* symbols
2. Groups symbols by semantic category (device_info, file_ops, media, etc.)
3. Generates new rules with accurate symbol names and prototypes

Usage:
    python scripts/regenerate_native_rules.py /path/to/libs
    python scripts/regenerate_native_rules.py --all input/
"""

import json
import sys
import os
from pathlib import Path
from collections import defaultdict, Counter

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("[-] pyelftools not installed. Run: pip install pyelftools")
    sys.exit(1)


# Mapping: symbol prefix pattern -> (category, profilingCategory, dataDirection)
SYMBOL_CATEGORY_MAP = {
    # Device identity / info
    'OH_NativeBundle': ('device_info', 'device_identity.software', 'source'),
    'OH_GetAbiList': ('device_info', 'device_identity.hardware', 'source'),
    'OH_GetBootloaderVersion': ('device_info', 'device_identity.software', 'source'),
    'OH_GetBrand': ('device_info', 'device_identity.software', 'source'),
    'OH_GetBuildHost': ('device_info', 'device_identity.software', 'source'),
    'OH_GetBuildRootHash': ('device_info', 'device_identity.software', 'source'),
    'OH_GetBuildTime': ('device_info', 'device_identity.software', 'source'),
    'OH_GetBuildType': ('device_info', 'device_identity.software', 'source'),
    'OH_GetBuildUser': ('device_info', 'device_identity.software', 'source'),
    'OH_GetDeviceId': ('device_identifier', 'device_identity.unique_id', 'source'),
    'OH_GetDeviceType': ('device_info', 'device_identity.hardware', 'source'),
    'OH_GetDisplayVersion': ('device_info', 'device_identity.software', 'source'),
    'OH_GetDistributionOS': ('device_info', 'device_identity.software', 'source'),
    'OH_GetFirstApiVersion': ('device_info', 'device_identity.software', 'source'),
    'OH_GetHardwareModel': ('device_info', 'device_identity.hardware', 'source'),
    'OH_GetIncrementalVersion': ('device_info', 'device_identity.software', 'source'),
    'OH_GetManufacture': ('device_info', 'device_identity.hardware', 'source'),
    'OH_GetMarketName': ('device_info', 'device_identity.software', 'source'),
    'OH_GetOSFullName': ('device_info', 'device_identity.software', 'source'),
    'OH_GetOsReleaseType': ('device_info', 'device_identity.software', 'source'),
    'OH_GetProductModel': ('device_info', 'device_identity.hardware', 'source'),
    'OH_GetProductSeries': ('device_info', 'device_identity.hardware', 'source'),
    'OH_GetSdkApiVersion': ('device_info', 'device_identity.software', 'source'),
    'OH_GetSecurityPatchTag': ('device_info', 'device_identity.software', 'source'),
    'OH_GetSoftwareModel': ('device_info', 'device_identity.software', 'source'),
    'OH_GetVersionId': ('device_info', 'device_identity.software', 'source'),

    # Media (audio/video codec)
    'OH_AVCodec': ('media_codec', 'media.audio', 'source'),
    'OH_AVDemuxer': ('media_codec', 'media.audio', 'source'),
    'OH_AVFormat': ('media_codec', 'media.audio', 'source'),
    'OH_AVMemory': ('media_codec', 'media.audio', 'source'),
    'OH_AVMuxer': ('media_codec', 'media.audio', 'source'),
    'OH_AVSource': ('media_codec', 'media.audio', 'source'),
    'OH_AudioDecoder': ('media_codec', 'media.audio', 'source'),
    'OH_AudioEncoder': ('media_codec', 'media.audio', 'source'),
    'OH_VideoDecoder': ('media_codec', 'media.camera', 'source'),
    'OH_VideoEncoder': ('media_codec', 'media.camera', 'source'),

    # File operations
    'OH_Asset': ('asset_ops', 'data_storage.filesystem', 'sink'),
    'OH_Asset_': ('asset_ops', 'data_storage.filesystem', 'sink'),

    # Network
    'OH_NetConn': ('network_info', 'network.connectivity', 'sink'),

    # Logging
    'OH_LOG': ('logging', 'app_analytics', 'sink'),
    'OH_Print': ('printing', 'app_analytics', 'sink'),

    # JSVM (JavaScript engine)
    'OH_JSVM': ('jsvm', 'app_analytics', 'sink'),

    # Media Descriptor
    'OH_MD': ('media_descriptor', 'media.audio', 'source'),
}

# Common system symbols to skip
SYSTEM_SYMBOLS_TO_SKIP = {
    '__cxa_finalize', '__stack_chk_fail', '__errno_location',
    'malloc', 'free', 'calloc', 'realloc',
    'memcpy', 'memmove', 'memset', 'memcmp',
    'strlen', 'strcpy', 'strncpy', 'strcmp', 'strncmp',
    'printf', 'fprintf', 'sprintf', 'snprintf',
    'fopen', 'fclose', 'fread', 'fwrite',
}


def extract_symbols(so_path: str) -> list:
    """Extract OH_* function symbols from a .so file."""
    symbols = []
    try:
        with open(so_path, 'rb') as f:
            ef = ELFFile(f)
            dynsym = ef.get_section_by_name('.dynsym')
            dynstr = ef.get_section_by_name('.dynstr')

            if not dynsym or not dynstr:
                return []

            for sym in dynsym.iter_symbols():
                name = dynstr.get_string(sym['st_name'])
                if not name or name in SYSTEM_SYMBOLS_TO_SKIP:
                    continue

                bind = sym['st_info']['bind']
                stype = sym['st_info']['type']

                # Only function symbols with global/weak binding
                if stype != 'STT_FUNC':
                    continue
                if bind not in ('STB_GLOBAL', 'STB_WEAK'):
                    continue

                symbols.append(name)
    except Exception as e:
        pass
    return symbols


def infer_category(symbol: str) -> tuple:
    """Infer category, profilingCategory, and dataDirection from symbol name."""
    # Check prefix map first
    for prefix, info in SYMBOL_CATEGORY_MAP.items():
        if symbol.startswith(prefix):
            return info

    # Default: unknown
    return ('unknown', 'unknown', 'source')


def main():
    # Default: scan input directory
    scan_dir = sys.argv[1] if len(sys.argv) > 1 else 'input'
    output_file = Path(__file__).parent.parent / 'native_privacy_apis.json'

    if scan_dir == '--help' or scan_dir == '-h':
        print("Usage: python regenerate_native_rules.py [/path/to/libs]")
        print("Scans .so files for OH_* symbols and regenerates native_privacy_apis.json")
        sys.exit(0)

    if not os.path.isdir(scan_dir):
        print(f"[-] Directory not found: {scan_dir}")
        sys.exit(1)

    print(f"[*] Scanning: {scan_dir}")

    # Collect all OH_* symbols from all SO files
    symbol_to_sources = defaultdict(set)  # symbol -> set of source files

    for root, dirs, files in os.walk(scan_dir):
        for fname in files:
            if not fname.endswith('.so'):
                continue
            so_path = os.path.join(root, fname)
            symbols = extract_symbols(so_path)

            for sym in symbols:
                if sym.startswith('OH_'):
                    symbol_to_sources[sym].add(os.path.basename(so_path))

    print(f"[*] Found {len(symbol_to_sources)} unique OH_* symbols")

    # Generate rules
    rules = []
    by_category = defaultdict(list)

    for symbol in sorted(symbol_to_sources.keys()):
        category, profiling_cat, direction = infer_category(symbol)
        sources = sorted(symbol_to_sources[symbol])

        rule = {
            'symbol': symbol,
            'prototype': f'unknown {symbol}(...)',
            'category': category,
            'profilingCategory': profiling_cat,
            'apiPackage': f'OpenHarmony.Native.{category.title()}',
            'dataDirection': direction,
            'matchModes': ['import_symbol', 'string_reference'],
        }
        rules.append(rule)
        by_category[category].append(symbol)

    # Summary by category
    print(f"\n[*] Rules by category:")
    for cat, syms in sorted(by_category.items(), key=lambda x: -len(x[1])):
        print(f"    {cat}: {len(syms)} symbols")

    # Backup existing
    backup_file = output_file.with_suffix('.json.bak')
    if output_file.exists() and not backup_file.exists():
        import shutil
        shutil.copy2(output_file, backup_file)
        print(f"\n[*] Backup created: {backup_file}")

    # Write new rules
    output_data = {'nativeApis': rules}
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)

    print(f"\n[+] Wrote {len(rules)} rules to {output_file}")
    print(f"    Categories: {len(by_category)}")
    print(f"    Total unique symbols: {len(symbol_to_sources)}")


if __name__ == '__main__':
    main()