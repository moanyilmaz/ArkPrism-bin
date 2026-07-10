package com.huawei.hisec;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

/**
 * ArkPrism binary privacy API analysis main entry.
 *
 * Default run via IDEA click:
 *   input/
 *     ├── C6917602215994202990_1.0.0/
 *     ├── C6917602221479724885_1.0.0/
 *     └── ...
 *
 * Output:
 *   out/
 *     └── batch_20260427_193000/
 *         ├── C6917602215994202990_1.0.0/
 *         │   └── C6917602215994202990_1.0.0_privacy_report.json
 *         ├── C6917602221479724885_1.0.0/
 *         │   └── C6917602221479724885_1.0.0_privacy_report.json
 *         ├── arkprism_20260427_193000.log
 *         └── batch_summary.json
 *
 * Manually specify a single hap directory:
 *   java com.huawei.hisec.Main sample/C6917602215994202990_1.0.0 privacy_apis.json out
 *
 * Output:
 *   out/
 *     └── C6917602215994202990_1.0.0_20260427_193000/
 *         ├── C6917602215994202990_1.0.0_privacy_report.json
 *         └── arkprism_20260427_193000.log
 *
 * Parameters:
 *   args[0] = input directory, default input
 *   args[1] = privacy_apis.json path, default privacy_apis.json
 *   args[2] = output root directory, default out
 */
public class Main {

    private static final String DEFAULT_INPUT_DIR = "benchmark_input";
    private static final String DEFAULT_RULE_JSON = "config/privacy_apis.json";
    private static final String DEFAULT_PROFILE_COMBINATION_JSON = "config/profile_combinations.json";
    private static final String DEFAULT_NATIVE_RULE_JSON = "config/native_privacy_apis.json";
    private static final String DEFAULT_OUTPUT_DIR = "benchmark_output";

    public static void main(String[] args) throws Exception {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String inputDirPath = args.length >= 1 ? args[0] : DEFAULT_INPUT_DIR;
        String ruleJsonPath = args.length >= 2 ? args[1] : DEFAULT_RULE_JSON;
        String outputRootPath = args.length >= 3 ? args[2] : DEFAULT_OUTPUT_DIR;
        String profileCombinationJsonPath = args.length >= 4
                ? args[3]
                : DEFAULT_PROFILE_COMBINATION_JSON;
        String nativeRuleJsonPath = args.length >= 5
                ? args[4]
                : DEFAULT_NATIVE_RULE_JSON;

        File inputDir = new File(inputDirPath);
        File ruleJsonFile = new File(ruleJsonPath);
        File outputRoot = new File(outputRootPath);
        File profileCombinationJsonFile = new File(profileCombinationJsonPath);
        File nativeRuleJsonFile = new File(nativeRuleJsonPath);

        
        if (!outputRoot.exists()) {
            outputRoot.mkdirs();
        }

        // Determine output directory and batch mode early for log file
        DiscoveryResult discovery = discoverTargets(inputDir);
        List<File> hapDirs = discovery.hapDirs;
        boolean batchMode = discovery.batchMode;

        File runOutputDir;
        if (batchMode) {
            runOutputDir = new File(outputRoot, "batch_" + timestamp);
        } else {
            File singleHapDir = hapDirs.isEmpty() ? null : hapDirs.get(0);
            runOutputDir = new File(outputRoot, (singleHapDir != null ? sanitizeFileName(singleHapDir.getName()) : "run") + "_" + timestamp);
        }

        if (!runOutputDir.exists()) {
            runOutputDir.mkdirs();
        }

        // Initialize log file in the output directory
        File logFile = Logger.generateLogFile(runOutputDir);
        Logger.init(logFile);

        try {
            Logger.log("[Log] Log file: " + logFile.getAbsolutePath());

            Logger.log("======================================================");
            Logger.log("[*] ArkPrism Binary Privacy Analyzer - Main");
            Logger.log("======================================================");
            Logger.log("[*] inputDir                  = " + inputDir.getAbsolutePath());
            Logger.log("[*] privacyApiRuleJsonFile    = " + ruleJsonFile.getAbsolutePath());
            Logger.log("[*] profileCombinationJsonFile= " + profileCombinationJsonFile.getAbsolutePath());
            Logger.log("[*] outputRoot                = " + outputRoot.getAbsolutePath());

            if (!inputDir.exists()) {
                Logger.error("[-] Input directory does not exist: " + inputDir.getAbsolutePath());
                return;
            }

            if (!ruleJsonFile.exists()) {
                Logger.error("[-] Rule file does not exist: " + ruleJsonFile.getAbsolutePath());
                return;
            }

            if (!profileCombinationJsonFile.exists()) {
                Logger.log("[!] Multi-source collaboration rule file not found, skipping multiSourceCollaborations: "
                        + profileCombinationJsonFile.getAbsolutePath());
            }

            if (hapDirs.isEmpty()) {
                Logger.error("[-] No hap directories found.");
                return;
            }

            Logger.log("[+] Found pending analysis hap directories: " + hapDirs.size());
            Logger.log("[*] batchMode = " + batchMode);
            Logger.log("[*] runOutputDir = " + runOutputDir.getAbsolutePath());

            PreciseSensitiveApiScanner arkTsScanner = new PreciseSensitiveApiScanner();
            SoVulnerabilityScanner nativeScanner = new SoVulnerabilityScanner();
            nativeScanner.setNativeRuleFile(nativeRuleJsonFile);

            List<BatchItem> batchItems = new ArrayList<>();

            int index = 0;
            for (File hapDir : hapDirs) {
                index++;

                Logger.log("");
                Logger.log("######################################################");
                Logger.log("[*] [" + index + "/" + hapDirs.size() + "] Analyzing HAP directory: " + hapDir.getName());
                Logger.log("######################################################");

                UnifiedPrivacyReport report = analyzeOneHapDirectory(
                        hapDir,
                        ruleJsonFile,
                        profileCombinationJsonFile,
                        arkTsScanner,
                        nativeScanner
                );

                File hapOutputDir;

                if (batchMode) {
                    hapOutputDir = new File(runOutputDir, sanitizeFileName(hapDir.getName()));
                } else {
                    hapOutputDir = runOutputDir;
                }

                if (!hapOutputDir.exists()) {
                    hapOutputDir.mkdirs();
                }

                String safeHapName = sanitizeFileName(hapDir.getName());
                File reportFile = new File(hapOutputDir, safeHapName + "_privacy_report.json");

                // Key: Output app report immediately after analysis
                saveReport(report, reportFile);

                BatchItem item = buildBatchItem(report, reportFile);
                batchItems.add(item);
            }

            if (batchMode) {
                BatchSummary batchSummary = buildBatchSummary(batchItems, inputDir, runOutputDir, timestamp);
                File summaryFile = new File(runOutputDir, "batch_summary.json");
                saveObject(batchSummary, summaryFile);

                Logger.log("");
                Logger.log("======================================================");
                Logger.log("[+] Batch analysis complete");
                Logger.log("[+] HAP count: " + batchItems.size());
                Logger.log("[+] Batch Summary: " + summaryFile.getAbsolutePath());
                Logger.log("======================================================");
            } else {
                Logger.log("");
                Logger.log("======================================================");
                Logger.log("[+] Single app analysis complete");
                Logger.log("[+] Output directory: " + runOutputDir.getAbsolutePath());
                Logger.log("======================================================");
            }

        } finally {
            Logger.close();
        }
    }

    // ======================================================
    // Single HAP Directory Analysis
    // ======================================================

    private static UnifiedPrivacyReport analyzeOneHapDirectory(
            File hapDir,
            File ruleJsonFile,
            File profileCombinationJsonFile,
            PreciseSensitiveApiScanner arkTsScanner,
            SoVulnerabilityScanner nativeScanner
    ) {
        UnifiedPrivacyReport report = new UnifiedPrivacyReport();

        report.projectName = hapDir.getName();
        report.projectDirectory = hapDir.getAbsolutePath();
        report.analysisTimestamp = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ").format(new Date());

        // --------------------------------------------------
        // 1. ArkTS / ABC Analysis
        // --------------------------------------------------
        PreciseSensitiveApiScanner.ArkTsScanResult arkTsResult;

        try {
            arkTsResult = arkTsScanner.scanDirectory(hapDir, ruleJsonFile);
        } catch (Throwable t) {
            arkTsResult = new PreciseSensitiveApiScanner.ArkTsScanResult();
            arkTsResult.warnings.add("ArkTS scanner crashed: " + safeMessage(t));
            Logger.log("[-] ArkTS scanner crashed: " + safeMessage(t));
        }

        /*
         * Key:
         * Add ArkTS usages first, then Native usages.
         * Because callChains.apiUsageIndex is generated starting from 0,
         * adding ArkTS first ensures callChains.apiUsageIndex correctly points to privacyApiUsages.
         */
        report.privacyApiUsages.addAll(arkTsResult.arktsApiUsages);
        report.callChains.addAll(arkTsResult.callChains);

        // --------------------------------------------------
        // 2. Native / SO Analysis
        // --------------------------------------------------
        SoVulnerabilityScanner.NativeScanResult nativeResult;

        try {
            nativeResult = nativeScanner.scanDirectory(hapDir);
        } catch (Throwable t) {
            nativeResult = new SoVulnerabilityScanner.NativeScanResult();
            nativeResult.warnings.add("Native scanner crashed: " + safeMessage(t));
            Logger.log("[-] Native scanner crashed: " + safeMessage(t));
        }

        /*
         * Native APIs are directly appended to privacyApiUsages.
         * No callChains are generated, and they do not participate in DataFlowExplorer.
         */
        report.privacyApiUsages.addAll(nativeResult.nativeApiUsages);

        // --------------------------------------------------
        // 3. Multi-Source Collaboration Detection
        // --------------------------------------------------
        // MultiSourceCollaborationAnalyzer filters Native hits internally (sourceLayer != "ArkTS").
        try {
            if (profileCombinationJsonFile != null && profileCombinationJsonFile.exists()) {
                report.multiSourceCollaborations =
                        MultiSourceCollaborationAnalyzer.analyze(report, profileCombinationJsonFile);
            } else {
                report.multiSourceCollaborations = new ArrayList<>();
            }
        } catch (Throwable t) {
            report.summary.warnings.add("Multi-source collaboration analyzer crashed: " + safeMessage(t));
            Logger.log("[-] Multi-source collaboration analyzer crashed: " + safeMessage(t));
        }

        // --------------------------------------------------
        // 4. Summary Statistics
        // --------------------------------------------------
        report.summary.analyzedHapCount = 1;
        report.summary.analyzedAbcCount = arkTsResult.analyzedAbcCount;
        report.summary.analyzedSoCount = nativeResult.analyzedSoCount;

        report.summary.arktsApiUsages = arkTsResult.arktsApiUsages.size();
        report.summary.nativeApiUsages = nativeResult.nativeApiUsages.size();
        report.summary.totalApiUsages = report.privacyApiUsages.size();

        report.summary.callChainCount = report.callChains.size();
        report.summary.controlStructureCount = countControlStructures(report.callChains);
        report.summary.sourceSnippetCount = countSourceSnippets(report.callChains);
        report.summary.dataSinkCount = countDataSinks(report.callChains);
        report.summary.multiSourceCollaborationCount =
                report.multiSourceCollaborations == null ? 0 : report.multiSourceCollaborations.size();

        report.summary.warnings.addAll(arkTsResult.warnings);
        report.summary.warnings.addAll(nativeResult.warnings);

        // Explicit GC to release memory between HAP analyses
        System.gc();

        return report;
    }

    // ======================================================
    // Input Target Discovery
    // ======================================================

    private static class DiscoveryResult {
        public List<File> hapDirs = new ArrayList<>();
        public boolean batchMode;
    }

    /**
     * Target discovery logic:
     *
     * 1. If input contains one or more "application root directories", batch mode is forced.
     *    This is the default behavior when running via IDEA click:
     *
     *      input/
     *        app1/
     *        app2/
     *
     *    Output:
     *      out/batch_timestamp/app1/app1_privacy_report.json
     *
     * 2. If input itself is a hap directory with no app subdirectories, single-app mode:
     *
     *      sample/Cxxx_1.0.0/
     *
     *    Output:
     *      out/Cxxx_1.0.0_timestamp/Cxxx_1.0.0_privacy_report.json
     */
    private static DiscoveryResult discoverTargets(File inputDir) {
        DiscoveryResult result = new DiscoveryResult();

        if (inputDir == null || !inputDir.exists() || !inputDir.isDirectory()) {
            return result;
        }

        /*
         * Prioritize checking first-level subdirectories of input.
         * This ensures IDEA's default run recognizes input/ as the batch root,
         * rather than misidentifying input as a single hap due to discovering input/app/libs/xxx.so.
         */
        List<File> childHapDirs = discoverImmediateHapChildren(inputDir);

        if (!childHapDirs.isEmpty()) {
            result.hapDirs.addAll(childHapDirs);
            result.batchMode = true;
            return result;
        }

        /*
         * If no hap subdirectories exist, check if inputDir itself is a single hap directory.
         */
        if (looksLikeHapDirectory(inputDir)) {
            result.hapDirs.add(inputDir);
            result.batchMode = false;
            return result;
        }

        return result;
    }

    /**
     * Only checks first-level subdirectories of input.
     * Internal directories like input/ets, input/libs should not be treated as hap packages.
     */
    private static List<File> discoverImmediateHapChildren(File inputDir) {
        List<File> result = new ArrayList<>();

        File[] children = inputDir.listFiles();
        if (children == null) {
            return result;
        }

        for (File child : children) {
            if (child == null || !child.isDirectory()) {
                continue;
            }

            String childName = child.getName();

            // Prevent internal directories in a single hap from being misidentified as applications.
            if (isCommonHapInternalDirectory(childName)) {
                continue;
            }

            if (looksLikeHapDirectory(child)) {
                result.add(child);
            }
        }

        result.sort(Comparator.comparing(File::getName));
        return result;
    }

    private static boolean isCommonHapInternalDirectory(String name) {
        if (name == null) {
            return false;
        }

        String n = name.toLowerCase(Locale.ROOT);

        return n.equals("ets")
                || n.equals("libs")
                || n.equals("lib")
                || n.equals("resources")
                || n.equals("resource")
                || n.equals("res")
                || n.equals("assets")
                || n.equals("entry")
                || n.equals("src")
                || n.equals("oh_modules")
                || n.equals("node_modules");
    }

    private static boolean looksLikeHapDirectory(File dir) {
        if (dir == null || !dir.exists() || !dir.isDirectory()) {
            return false;
        }

        try (Stream<java.nio.file.Path> stream = Files.walk(dir.toPath())) {
            return stream
                    .filter(Files::isRegularFile)
                    .anyMatch(p -> {
                        String s = p.toString().toLowerCase(Locale.ROOT);
                        return s.endsWith(".abc") || s.endsWith(".so");
                    });
        } catch (IOException e) {
            return false;
        }
    }

    // ======================================================
    // Report Saving
    // ======================================================

    private static void saveReport(UnifiedPrivacyReport report, File outputFile) {
        saveObject(report, outputFile);
        Logger.log("[+] App report saved: " + outputFile.getAbsolutePath());
    }

    private static void saveObject(Object obj, File outputFile) {
        try {
            File parent = outputFile.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }

            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);
            mapper.writeValue(outputFile, obj);

        } catch (IOException e) {
            Logger.log("[-] JSON save failed: " + outputFile.getAbsolutePath());
            Logger.log("[-] " + e.getMessage());
        }
    }

    // ======================================================
    // Batch Summary
    // ======================================================

    private static BatchItem buildBatchItem(UnifiedPrivacyReport report, File reportFile) {
        BatchItem item = new BatchItem();

        item.projectName = report.projectName;
        item.projectDirectory = report.projectDirectory;
        item.outputJson = reportFile.getAbsolutePath();

        item.totalApiUsages = report.summary.totalApiUsages;
        item.arktsApiUsages = report.summary.arktsApiUsages;
        item.nativeApiUsages = report.summary.nativeApiUsages;
        item.callChainCount = report.summary.callChainCount;
        item.controlStructureCount = report.summary.controlStructureCount;
        item.sourceSnippetCount = report.summary.sourceSnippetCount;
        item.dataSinkCount = report.summary.dataSinkCount;
        item.multiSourceCollaborationCount = report.summary.multiSourceCollaborationCount;

        item.analyzedAbcCount = report.summary.analyzedAbcCount;
        item.analyzedSoCount = report.summary.analyzedSoCount;
        item.warningCount = report.summary.warnings == null ? 0 : report.summary.warnings.size();

        return item;
    }

    private static int countDataSinks(List<UnifiedPrivacyReport.CallChainReport> callChains) {
        if (callChains == null || callChains.isEmpty()) {
            return 0;
        }

        int count = 0;

        for (UnifiedPrivacyReport.CallChainReport chain : callChains) {
            if (chain != null && chain.dataSinks != null) {
                count += chain.dataSinks.size();
            }
        }

        return count;
    }

    private static int countControlStructures(List<UnifiedPrivacyReport.CallChainReport> callChains) {
        if (callChains == null || callChains.isEmpty()) {
            return 0;
        }

        int count = 0;

        for (UnifiedPrivacyReport.CallChainReport chain : callChains) {
            if (chain != null && chain.controlStructures != null) {
                count += chain.controlStructures.size();
            }
        }

        return count;
    }

    private static int countSourceSnippets(List<UnifiedPrivacyReport.CallChainReport> callChains) {
        if (callChains == null || callChains.isEmpty()) {
            return 0;
        }

        int count = 0;

        for (UnifiedPrivacyReport.CallChainReport chain : callChains) {
            if (chain != null && chain.sourceSnippets != null) {
                count += chain.sourceSnippets.size();
            }
        }

        return count;
    }

    private static BatchSummary buildBatchSummary(
            List<BatchItem> items,
            File inputDir,
            File batchOutputDir,
            String batchTimestamp
    ) {
        BatchSummary summary = new BatchSummary();

        summary.inputDirectory = inputDir.getAbsolutePath();
        summary.outputDirectory = batchOutputDir.getAbsolutePath();
        summary.batchTimestamp = batchTimestamp;
        summary.totalHapCount = items.size();

        for (BatchItem item : items) {
            summary.totalApiUsages += item.totalApiUsages;
            summary.arktsApiUsages += item.arktsApiUsages;
            summary.nativeApiUsages += item.nativeApiUsages;
            summary.totalCallChains += item.callChainCount;
            summary.totalControlStructures += item.controlStructureCount;
            summary.totalSourceSnippets += item.sourceSnippetCount;
            summary.totalDataSinks += item.dataSinkCount;
            summary.totalMultiSourceCollaborations += item.multiSourceCollaborationCount;

            summary.totalAnalyzedAbcCount += item.analyzedAbcCount;
            summary.totalAnalyzedSoCount += item.analyzedSoCount;
            summary.totalWarningCount += item.warningCount;
        }

        summary.items.addAll(items);
        return summary;
    }

    public static class BatchSummary {
        public String inputDirectory;
        public String outputDirectory;
        public String batchTimestamp;

        public int totalHapCount;
        public int totalApiUsages;
        public int arktsApiUsages;
        public int nativeApiUsages;

        public int totalCallChains;
        public int totalControlStructures;
        public int totalSourceSnippets;
        public int totalDataSinks;
        public int totalMultiSourceCollaborations;

        public int totalAnalyzedAbcCount;
        public int totalAnalyzedSoCount;
        public int totalWarningCount;

        public List<BatchItem> items = new ArrayList<>();
    }

    public static class BatchItem {
        public String projectName;
        public String projectDirectory;
        public String outputJson;

        public int totalApiUsages;
        public int arktsApiUsages;
        public int nativeApiUsages;

        public int callChainCount;
        public int controlStructureCount;
        public int sourceSnippetCount;
        public int dataSinkCount;
        public int multiSourceCollaborationCount;

        public int analyzedAbcCount;
        public int analyzedSoCount;
        public int warningCount;
    }

    // ======================================================
    // Utility Methods
    // ======================================================

    private static String sanitizeFileName(String name) {
        if (name == null || name.isBlank()) {
            return "unknown";
        }

        String s = name.trim();
        s = s.replaceAll("[\\\\/:*?\"<>|]", "_");
        s = s.replaceAll("\\s+", "_");

        if (s.length() > 120) {
            s = s.substring(0, 120);
        }

        return s;
    }

    private static String safeMessage(Throwable t) {
        if (t == null) {
            return "unknown error";
        }

        String msg = t.getMessage();
        if (msg == null || msg.isBlank()) {
            return t.getClass().getName();
        }

        return msg;
    }
}