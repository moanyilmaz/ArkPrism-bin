#!/usr/bin/env python3
"""Translate Chinese comments to English in Java files."""

import os
import re

# Common translations
TRANSLATIONS = {
    # Main class output
    'System.out.println("[*] 分析 HAP 解压目录: ': 'System.out.println("[*] Analyzing HAP directory: ',
    'System.out.println("[*] 发现待分析 hap 解压目录: ': 'System.out.println("[+] Found pending analysis hap directories: ',
    'System.err.println("[-] 输入目录不存在: ': 'System.err.println("[-] Input directory does not exist: ',
    'System.err.println("[-] 规则文件不存在: ': 'System.err.println("[-] Rule file does not exist: ',
    'System.err.println("[!] 多源协同规则文件不存在，将跳过 multiSourceCollaborations: ': 'System.err.println("[!] Multi-source collaboration rule file not found, skipping multiSourceCollaborations: ',
    'System.err.println("[-] 未发现 hap 解压目录。");': 'System.err.println("[-] No hap directories found.");',
    'System.out.println("[+] 单应用分析完成");': 'System.out.println("[+] Single app analysis complete");',
    'System.out.println("[+] 输出目录: ': 'System.out.println("[+] Output directory: ',

    # Javadoc translations
    'ArkPrism 二进制隐私 API 分析总入口。': 'ArkPrism binary privacy API analysis main entry.',
    '默认 IDEA 直接点击运行：': 'Default run via IDEA click:',
    '输出：': 'Output:',
    '手动传入单个 hap 解压目录：': 'Manually specify a single hap directory:',
    '参数：': 'Parameters:',
    'args[0] = 输入目录，默认 input': 'args[0] = input directory, default input',
    'args[1] = privacy_apis.json 路径，默认 privacy_apis.json': 'args[1] = privacy_apis.json path, default privacy_apis.json',
    'args[2] = 输出根目录，默认 out': 'args[2] = output root directory, default out',
    '// 打印 JVM 内存信息，用于排查 Andersen 内存不足问题': '// Print JVM memory info for debugging Andersen memory issues',
    'System.out.println("[-] 未发现 hap 解压目录。");': 'System.err.println("[-] No hap directories found.");',
    '// 关键：每分析完一个应用，立即输出一个应用报告。': '// Key: Output app report immediately after analysis',
    'System.out.println("[*] 检测到单 Hap 模式，文件名格式: ");': 'System.out.println("[*] Single Hap mode detected, filename format: ");',
    'System.out.println("[*] 分析 ABC: ': 'System.out.println("[*] Analyzing ABC: ',
    'System.out.println("[-] 双解析器均失败，跳过。");': 'System.out.println("[-] Both parsers failed, skipping.");',
    'System.out.println("[-] 当前 ABC 未命中敏感 API。");': 'System.out.println("[-] No sensitive API hits in current ABC.");',
    'System.out.println("[+] 当前 ABC 命中敏感 API: ': 'System.out.println("[+] Current ABC sensitive API hits: ',
    'System.out.println("[-] 当前 ABC 只有 CHAIN_EVIDENCE 命中，无 BODY_HIT，不构建调用链。");': 'System.out.println("[-] Current ABC has only CHAIN_EVIDENCE hits, no BODY_HIT, skipping call chain.");',
    'System.out.println("[+] ArkTS ABC 扫描完成，API 命中数: ': 'System.out.println("[+] ArkTS ABC scan complete, API hits: ',
    'System.out.println("[+] ArkTS 调用链数量: ': 'System.out.println("[+] ArkTS call chains: ',
    'System.out.println("[*] 构建调用图 ANDERSEN...");': 'System.out.println("[*] Building call graph with ANDERSEN...");',
    'System.out.println("[+] 调用链抽取完成: ': 'System.out.println("[+] Call chain extraction complete: ',
    'System.out.println("[*] 尝试执行正向数据流追踪...");': 'System.out.println("[*] Attempting forward data flow analysis...");',

    # Main class
    'System.out.println("=======================================================");': 'System.out.println("=======================================================");',
    'System.out.println("[*] ArkPrism Binary Privacy Analyzer - Main");': 'System.out.println("[*] ArkPrism Binary Privacy Analyzer - Main");',
    'System.out.println("[*] inputDir                  = ': 'System.out.println("[*] inputDir                  = ',
    'System.out.println("[*] privacyApiRuleJsonFile    = ': 'System.out.println("[*] privacyApiRuleJsonFile    = ',
    'System.out.println("[*] profileCombinationJsonFile= ': 'System.out.println("[*] profileCombinationJsonFile= ',
    'System.out.println("[*] outputRoot                = ': 'System.out.println("[*] outputRoot                = ',
    'System.out.println("[+] 发现待分析 hap 解压目录: ': 'System.out.println("[+] Found pending analysis hap directories: ',
    'System.out.println("[*] batchMode = true");': 'System.out.println("[*] batchMode = true");',
    'System.out.println("[*] runOutputDir = ': 'System.out.println("[*] runOutputDir = ',
    'System.out.println("######################################################");': 'System.out.println("######################################################");',
    'System.out.println("[*] [': 'System.out.println("[*] [',
    'System.out.println(" 分析 HAP 解压目录: ': 'System.out.println(" Analyzing HAP directory: ',
    'System.out.println("######################################################");': 'System.out.println("######################################################");',
    'System.out.println("[*] ArkTS ABC Sensitive API Scanner");': 'System.out.println("[*] ArkTS ABC Sensitive API Scanner");',
    'System.out.println("[*] targetDirectory = ': 'System.out.println("[*] targetDirectory = ',
    'System.out.println("[*] ruleJsonFile = ': 'System.out.println("[*] ruleJsonFile = ',
    'System.out.println("[*] Excluding ': 'System.out.println("[*] Excluding ',
    'System.out.println(" APIs with dataDirection=excluded");': 'System.out.println(" APIs with dataDirection=excluded");',
    'System.out.println("######################################################");': 'System.out.println("######################################################");',
    'System.out.println("======================================================");': 'System.out.println("======================================================");',
    'System.out.println("[*] Native SO Scanner");': 'System.out.println("[*] Native SO Scanner");',
    'System.out.println("[*] targetDirectory = ': 'System.out.println("[*] targetDirectory = ',
    'System.out.println("[*] nativeRuleFile  = ': 'System.out.println("[*] nativeRuleFile  = ',
    'System.out.println("[*] discovered so files = ': 'System.out.println("[*] discovered so files = ',
    'System.out.println("------------------------------------------------------");': 'System.out.println("------------------------------------------------------");',
    'System.out.println("[*] 跳过公共运行时库: ': 'System.out.println("[*] Skip common runtime library: ',
    'System.out.println("[*] 分析 SO: ': 'System.out.println("[*] Analyzing SO: ',
    'System.out.println("[*] 路径: ': 'System.out.println("[*] Path: ',
    'System.out.println("[-] 未命中 Native 隐私 API。exitCode=0");': 'System.out.println("[-] No Native privacy API hits. exitCode=0");',
    '[PreciseScanner] SSA skipped (no body): ': '[PreciseScanner] SSA skipped (no body): ',
    'System.out.println("[*] SSA+TypeInfer transformed ': 'System.out.println("[*] SSA+TypeInfer transformed ',
    'System.out.println("[*] ARKTSV1 raw hits: ': 'System.out.println("[*] ARKTSV1 raw hits: ',
    'System.out.println("[*] after dedup hits: ': 'System.out.println("[*] after dedup hits: ',
    'System.out.println("[+] Dual-parser stats: V2=0, V1=1, dual=0, V2-only hits=0");': 'System.out.println("[+] Dual-parser stats: V2=0, V1=1, dual=0, V2-only hits=0");',
    'System.out.println("[+] ArkTS ABC 扫描完成，API 命中数: ': 'System.out.println("[+] ArkTS ABC scan complete, API hits: ',
    'System.out.println("[+] ArkTS 调用链数量: ': 'System.out.println("[+] ArkTS call chains: ',
    'System.out.println("[+] Native SO 扫描完成，命中数: ': 'System.out.println("[+] Native SO scan complete, hits: ',
    'System.out.println("[+] 应用报告已保存: ': 'System.out.println("[+] App report saved: ',
    'System.out.println("[*] 构建调用图 ANDERSEN...");': 'System.out.println("[*] Building call graph with ANDERSEN...");',
    'System.out.println("[+] 调用链抽取完成: ': 'System.out.println("[+] Call chain extraction complete: ',
    'System.out.println("[*] 尝试执行正向数据流追踪...");': 'System.out.println("[*] Attempting forward data flow analysis...");',

    # Summary
    'System.out.println("======================================================");': 'System.out.println("======================================================");',
    'System.out.println("[+] 批量分析完成");': 'System.out.println("[+] Batch analysis complete");',
    'System.out.println("[+] HAP 数量: ': 'System.out.println("[+] HAP count: ',
    'System.out.println("[+] Batch Summary: ': 'System.out.println("[+] Batch Summary: ',
    'System.out.println("======================================================");': 'System.out.println("======================================================");',

    # Errors
    'System.err.println("[-] ': 'System.err.println("[-] ',

    # Section headers
    '// ======================================================\n    // 1. 对外主入口：扫描一个 hap 解压目录': '// ======================================================\n    // 1. Main Entry: Scan One HAP Directory',
    '// ======================================================\n    // 2. 命中结果模型': '// ======================================================\n    // 2. Hit Result Models',
    '// ======================================================\n    // 3. 对外主入口：扫描一个 hap 解压目录': '// ======================================================\n    // 3. Main Entry: Scan One HAP Directory',
    '// ======================================================\n    // 4. 为单个 ABC 构建调用链和数据流': '// ======================================================\n    // 4. Build Call Chains and Data Flow for One ABC',
    '// ======================================================\n    // 6. 原有 scanHiFile 和匹配逻辑': '// ======================================================\n    // 6. Original scanHiFile and Matching Logic',
    '// ======================================================\n    // 7. 调用链、方法体、SINK、purposeHint': '// ======================================================\n    // 7. Call Chain, Method Body, SINK, purposeHint',
    '// ======================================================\n    // 8. 规则与名称解析': '// ======================================================\n    // 8. Rule and Name Resolution',
    '// ======================================================\n    // 9. 推断与格式化工具': '// ======================================================\n    // 9. Inference and Formatting Utilities',
    '// ======================================================\n    // 10. 安全访问工具': '// ======================================================\n    // 10. Safe Access Utilities',
    '// ======================================================\n    // 11. 单独调试入口': '// ======================================================\n    // 11. Standalone Debug Entry Point',

    # Comments
    '兼容源码侧规则字段': 'Compatible with source-code rule fields',
    '// Uni-app /跨平台组件': '// Uni-app / cross-platform component',

    # Javadoc
    'ArkTS / ABC 敏感 API 扫描器。': 'ArkTS / ABC Sensitive API Scanner.',
    '当前职责：': 'Responsibilities:',
    '1. 扫描 hap 解压目录下所有 .abc 文件；': '1. Scan all .abc files in extracted hap directory',
    '2. 根据 privacy_apis.json 识别 ArkTS 层敏感 API；': '2. Identify sensitive ArkTS APIs based on privacy_apis.json',
    '3. 对 ArkTS 命中构建调用链；': '3. Build call chains for ArkTS API hits',
    '4. 对 ArkTS 命中尝试执行正向数据流追踪；': '4. Perform forward data flow analysis on ArkTS hits',
    '5. 输出 UnifiedPrivacyReport.ApiUsage 与 UnifiedPrivacyReport.CallChainReport。': '5. Output UnifiedPrivacyReport.ApiUsage and UnifiedPrivacyReport.CallChainReport',
    '注意：': 'Note:',
    'Native/.so 命中不在这里处理，由 SoVulnerabilityScanner 负责。': 'Native/.so hits are handled by SoVulnerabilityScanner',
}


def translate_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original = content

    for cn, en in TRANSLATIONS.items():
        content = content.replace(cn, en)

    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False


def main():
    base_dir = 'src/main/java/com/huawei/hisec'
    files = [
        'Main.java',
        'MultiSourceCollaborationAnalyzer.java',
        'UnifiedPrivacyReport.java',
        'SoVulnerabilityScanner.java',
        'CallGraphExplorer.java',
        'AliasAnalyzer.java',
        'PrivacyCatalog.java',
        'PreciseSensitiveApiScanner.java',
        'DataFlowExplorer.java',
    ]

    for f in files:
        filepath = os.path.join(base_dir, f)
        if os.path.exists(filepath):
            if translate_file(filepath):
                print(f'Translated: {f}')
            else:
                print(f'No changes: {f}')

    print('Done')


if __name__ == '__main__':
    main()