package com.huawei.hisec;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.huawei.hianalyzer.analysis.Stage;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.base.HiFunction;
import com.huawei.hianalyzer.analysis.graph.callgraph.CallGraph;
import com.huawei.hianalyzer.analysis.graph.callgraph.pta.andersen.Andersen;
import com.huawei.hianalyzer.frontend.metainterface.SourceLang;
import com.huawei.hianalyzer.ir.stmt.CallStmt;
import com.huawei.hianalyzer.ir.stmt.Stmt;
import com.huawei.hianalyzer.ir.value.Local;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Decision Experiment 1: Official Metadata Baseline vs CAIR Residual Analysis
 *
 * Purpose: Determine how many call sites HiAnalyzer's official metadata
 * (getFullApiNameByStmt / getAllStmtApiNameMap) can uniquely resolve,
 * and how many remain ambiguous — the "residual" that PrismBind must handle.
 *
 * Classification of each call site:
 * - DIRECT_UNIQUE: Official metadata gives a full API name that maps to exactly 1 rule
 * - INDIRECT_AMBIGUOUS: Official metadata gives a partial name matching multiple rules (different namespaces)
 * - UNRESOLVED: Official metadata returns null or empty
 *
 * Additional analysis:
 * - For INDIRECT_AMBIGUOUS sites: how many distinct namespaces compete?
 * - Do the competing namespaces have different security semantics (privacy vs non-privacy)?
 * - How does CAIR's resolution compare to the baseline?
 */
public class BaselineAnalyzer {

    // ======================================================
    // Data Structures
    // ======================================================

    static class PrivacyApiRule {
        public String namespace;
        public String method;
        public String apiPackage;
        public String profilingCategory;
        public String dataDirection;
    }

    static class CallSiteClassification {
        String hapName;
        Stmt stmt;
        String fullApiName;         // Official metadata result
        String methodName;          // Extracted method name
        String classification;      // DIRECT_UNIQUE, INDIRECT_AMBIGUOUS, UNRESOLVED
        List<String> matchingNamespaces;  // All namespaces matching the method name
        List<String> matchingCategories;  // Privacy categories of matching rules
        boolean hasPrivacyConflict; // Multiple namespaces with different privacy categories
        int candidateCount;         // Number of rule candidates
        String cairResolution;      // CAIR's resolution (if available)
        boolean cairAgrees;         // Does CAIR pick the same namespace as the unique match?
        String fileName;
        String functionName;
    }

    static class BaselineReport {
        String hapName;
        int totalCallSites;
        int directUnique;
        int indirectAmbiguous;
        int unresolved;
        int ambiguousWithPrivacyConflict;
        int ambiguousNoPrivacyConflict;
        Map<Integer, Integer> candidateCountDistribution = new TreeMap<>();
        List<CallSiteClassification> details = new ArrayList<>();
    }

    // ======================================================
    // Main
    // ======================================================

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: BaselineAnalyzer <inputDir> <ruleJson> [outputJson]");
            System.out.println("  inputDir: directory containing HAP subdirectories");
            System.out.println("  ruleJson: privacy_apis.json rule file");
            System.out.println("  outputJson: output report path (optional)");
            return;
        }

        String inputDir = args[0];
        String ruleJson = args[1];
        String outputJson = args.length > 2 ? args[2] : "baseline_report.json";

        // Load rules
        List<PrivacyApiRule> allRules = loadRules(ruleJson);
        System.out.println("[*] Loaded " + allRules.size() + " privacy API rules");

        // Build method -> rules index
        Map<String, List<PrivacyApiRule>> methodToRules = new LinkedHashMap<>();
        for (PrivacyApiRule rule : allRules) {
            methodToRules.computeIfAbsent(rule.method, k -> new ArrayList<>()).add(rule);
        }

        // Build namespace.method -> rule index for direct matching
        Map<String, PrivacyApiRule> nsMethodToRule = new LinkedHashMap<>();
        for (PrivacyApiRule rule : allRules) {
            nsMethodToRule.put(rule.namespace + "." + rule.method, rule);
        }

        System.out.println("[*] Unique methods: " + methodToRules.size());
        System.out.println("[*] Methods with multiple namespaces: " +
                methodToRules.entrySet().stream().filter(e -> e.getValue().size() > 1).count());

        // Find HAP directories
        File input = new File(inputDir);
        File[] hapDirs = input.listFiles(File::isDirectory);
        if (hapDirs == null || hapDirs.length == 0) {
            System.out.println("[ERROR] No HAP directories found in " + inputDir);
            return;
        }
        Arrays.sort(hapDirs, Comparator.comparing(File::getName));

        List<BaselineReport> reports = new ArrayList<>();
        int grandTotal = 0, grandDirect = 0, grandAmbiguous = 0, grandUnresolved = 0;
        int grandPrivacyConflict = 0;

        for (File hapDir : hapDirs) {
            BaselineReport report = analyzeHap(hapDir, allRules, methodToRules, nsMethodToRule);
            reports.add(report);

            grandTotal += report.totalCallSites;
            grandDirect += report.directUnique;
            grandAmbiguous += report.indirectAmbiguous;
            grandUnresolved += report.unresolved;
            grandPrivacyConflict += report.ambiguousWithPrivacyConflict;

            System.out.println("\n=== " + report.hapName + " ===");
            System.out.println("  Total call sites: " + report.totalCallSites);
            System.out.println("  DIRECT_UNIQUE:    " + report.directUnique);
            System.out.println("  INDIRECT_AMBIG:   " + report.indirectAmbiguous);
            System.out.println("  UNRESOLVED:       " + report.unresolved);
            System.out.println("  Ambig w/ privacy conflict: " + report.ambiguousWithPrivacyConflict);
            System.out.println("  Ambig w/o privacy conflict: " + report.ambiguousNoPrivacyConflict);
            if (!report.candidateCountDistribution.isEmpty()) {
                System.out.println("  Candidate count distribution:");
                for (var entry : report.candidateCountDistribution.entrySet()) {
                    System.out.println("    " + entry.getKey() + " candidates: " + entry.getValue() + " sites");
                }
            }
        }

        // Summary
        System.out.println("\n======================================================");
        System.out.println("GRAND SUMMARY");
        System.out.println("======================================================");
        System.out.println("Total call sites:              " + grandTotal);
        System.out.println("DIRECT_UNIQUE (official OK):   " + grandDirect +
                " (" + String.format("%.1f%%", 100.0 * grandDirect / Math.max(grandTotal, 1)) + ")");
        System.out.println("INDIRECT_AMBIGUOUS (residual): " + grandAmbiguous +
                " (" + String.format("%.1f%%", 100.0 * grandAmbiguous / Math.max(grandTotal, 1)) + ")");
        System.out.println("UNRESOLVED:                    " + grandUnresolved +
                " (" + String.format("%.1f%%", 100.0 * grandUnresolved / Math.max(grandTotal, 1)) + ")");
        System.out.println("Ambig w/ privacy CONFLICT:     " + grandPrivacyConflict +
                " (" + String.format("%.1f%%", 100.0 * grandPrivacyConflict / Math.max(grandAmbiguous, 1)) + " of ambiguous)");
        System.out.println("Ambig w/o privacy conflict:    " + (grandAmbiguous - grandPrivacyConflict));

        // Also show what the ambiguous sites look like
        System.out.println("\n--- Sample AMBIGUOUS sites (first 20) ---");
        int shown = 0;
        for (BaselineReport r : reports) {
            for (CallSiteClassification c : r.details) {
                if ("INDIRECT_AMBIGUOUS".equals(c.classification) && shown < 20) {
                    System.out.printf("  [%s] %s -> candidates=%d ns=%s conflict=%s%n",
                            c.hapName, c.methodName, c.candidateCount,
                            c.matchingNamespaces, c.hasPrivacyConflict);
                    shown++;
                }
            }
        }

        // Show UNRESOLVED sites
        System.out.println("\n--- UNRESOLVED sites (first 10) ---");
        shown = 0;
        for (BaselineReport r : reports) {
            for (CallSiteClassification c : r.details) {
                if ("UNRESOLVED".equals(c.classification) && shown < 10) {
                    System.out.printf("  [%s] stmt=%s func=%s%n",
                            c.hapName, c.stmt, c.functionName);
                    shown++;
                }
            }
        }

        // Write JSON report
        writeReport(reports, outputJson);
        System.out.println("\n[*] Report written to " + outputJson);
    }

    // ======================================================
    // Per-HAP Analysis
    // ======================================================

    static BaselineReport analyzeHap(File hapDir, List<PrivacyApiRule> allRules,
                                      Map<String, List<PrivacyApiRule>> methodToRules,
                                      Map<String, PrivacyApiRule> nsMethodToRule) {
        BaselineReport report = new BaselineReport();
        report.hapName = hapDir.getName();

        // Find ABC files
        List<File> abcFiles = new ArrayList<>();
        findAbcFiles(hapDir, abcFiles);
        if (abcFiles.isEmpty()) {
            System.out.println("[WARN] No ABC files in " + hapDir.getName());
            return report;
        }

        for (File abcFile : abcFiles) {
            try {
                analyzeAbc(abcFile, allRules, methodToRules, nsMethodToRule, report);
            } catch (Throwable t) {
                System.out.println("[ERROR] Failed to analyze " + abcFile.getName() + ": " + t.getMessage());
            }
        }

        return report;
    }

    static void findAbcFiles(File dir, List<File> result) {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.getName().endsWith(".abc")) {
                result.add(f);
            } else if (f.isDirectory()) {
                findAbcFiles(f, result);
            }
        }
    }

    static void analyzeAbc(File abcFile, List<PrivacyApiRule> allRules,
                            Map<String, List<PrivacyApiRule>> methodToRules,
                            Map<String, PrivacyApiRule> nsMethodToRule,
                            BaselineReport report) throws IOException {

        HiFile hiFile = Stage.createHiFile(abcFile.getAbsolutePath(), SourceLang.ARKTSV1);
        if (hiFile == null) return;

        // Get official metadata: stmt -> full API name
        Map<Stmt, String> stmtApiMap;
        try {
            stmtApiMap = hiFile.getAllStmtApiNameMap();
        } catch (Throwable t) {
            System.out.println("[WARN] getAllStmtApiNameMap failed for " + abcFile.getName());
            return;
        }
        if (stmtApiMap == null || stmtApiMap.isEmpty()) return;

        for (Map.Entry<Stmt, String> entry : stmtApiMap.entrySet()) {
            Stmt stmt = entry.getKey();
            String fullApiName = entry.getValue();

            if (fullApiName == null || fullApiName.isEmpty()) {
                // UNRESOLVED: official metadata returns nothing
                CallSiteClassification c = new CallSiteClassification();
                c.hapName = report.hapName;
                c.stmt = stmt;
                c.classification = "UNRESOLVED";
                c.candidateCount = 0;
                try {
                    HiFunction func = stmt.getHiFunction();
                    c.functionName = func != null ? func.getSignature().toString() : "?";
                } catch (Throwable ignored) { c.functionName = "?"; }
                report.details.add(c);
                report.totalCallSites++;
                report.unresolved++;
                continue;
            }

            // Parse the full API name
            PreciseSensitiveApiScanner.ResolvedNameInfo nameInfo =
                    NamePathMatcher.parseResolvedName(fullApiName);
            String methodName = nameInfo.lastToken;

            if (methodName == null || methodName.isEmpty()) {
                CallSiteClassification c = new CallSiteClassification();
                c.hapName = report.hapName;
                c.stmt = stmt;
                c.fullApiName = fullApiName;
                c.classification = "UNRESOLVED";
                c.candidateCount = 0;
                report.details.add(c);
                report.totalCallSites++;
                report.unresolved++;
                continue;
            }

            // Try direct namespace.method match first
            String nsMethodKey = nameInfo.rootQualifier + "." + methodName;
            PrivacyApiRule directMatch = nsMethodToRule.get(nsMethodKey);

            // Also check by method name alone
            List<PrivacyApiRule> methodMatches = methodToRules.getOrDefault(methodName, Collections.emptyList());

            // Try to extract namespace from path tokens
            List<String> possibleNamespaces = new ArrayList<>();
            if (nameInfo.rootQualifier != null && !nameInfo.rootQualifier.isEmpty()) {
                possibleNamespaces.add(nameInfo.rootQualifier);
            }
            for (String token : nameInfo.pathTokens) {
                if (!possibleNamespaces.contains(token)) {
                    possibleNamespaces.add(token);
                }
            }

            // Filter method matches by possible namespaces
            List<PrivacyApiRule> namespaceFilteredMatches = new ArrayList<>();
            if (!possibleNamespaces.isEmpty()) {
                for (PrivacyApiRule rule : methodMatches) {
                    for (String ns : possibleNamespaces) {
                        if (rule.namespace.contains(ns) || ns.contains(rule.namespace)) {
                            namespaceFilteredMatches.add(rule);
                            break;
                        }
                    }
                }
            }

            CallSiteClassification c = new CallSiteClassification();
            c.hapName = report.hapName;
            c.stmt = stmt;
            c.fullApiName = fullApiName;
            c.methodName = methodName;

            try {
                HiFunction func = stmt.getHiFunction();
                c.functionName = func != null ? func.getSignature().toString() : "?";
            } catch (Throwable ignored) { c.functionName = "?"; }

            // Classify
            if (directMatch != null) {
                // Official metadata + namespace uniquely identifies a privacy API rule
                c.classification = "DIRECT_UNIQUE";
                c.matchingNamespaces = Collections.singletonList(directMatch.namespace);
                c.matchingCategories = Collections.singletonList(directMatch.profilingCategory);
                c.candidateCount = 1;
                c.hasPrivacyConflict = false;
                report.directUnique++;
            } else if (namespaceFilteredMatches.size() == 1) {
                // Method + namespace hints narrow to exactly 1 rule
                c.classification = "DIRECT_UNIQUE";
                c.matchingNamespaces = Collections.singletonList(namespaceFilteredMatches.get(0).namespace);
                c.matchingCategories = Collections.singletonList(namespaceFilteredMatches.get(0).profilingCategory);
                c.candidateCount = 1;
                c.hasPrivacyConflict = false;
                report.directUnique++;
            } else if (!methodMatches.isEmpty()) {
                // Method name matches multiple rules (different namespaces)
                c.classification = "INDIRECT_AMBIGUOUS";
                c.matchingNamespaces = methodMatches.stream()
                        .map(r -> r.namespace).distinct().collect(Collectors.toList());
                c.matchingCategories = methodMatches.stream()
                        .map(r -> r.profilingCategory).distinct().collect(Collectors.toList());
                c.candidateCount = methodMatches.size();
                c.hasPrivacyConflict = c.matchingCategories.size() > 1;
                report.indirectAmbiguous++;
                if (c.hasPrivacyConflict) {
                    report.ambiguousWithPrivacyConflict++;
                } else {
                    report.ambiguousNoPrivacyConflict++;
                }
                report.candidateCountDistribution.merge(c.candidateCount, 1, Integer::sum);
            } else {
                // No rule matches at all — method name not in privacy API catalog
                // This is NOT unresolved (official metadata works), but the method
                // is simply not a privacy API
                // We don't count these as they are not relevant to PrismBind
                continue; // Skip non-privacy methods entirely
            }

            report.details.add(c);
            report.totalCallSites++;
        }
    }

    // ======================================================
    // Rule Loading
    // ======================================================

    static List<PrivacyApiRule> loadRules(String ruleJsonPath) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

        // The JSON structure is an array: [ { "systemPackage": "...", "privacyApis": [ { "method": "...", ... } ] } ]
        List<Map<String, Object>> apiPackages = mapper.readValue(new File(ruleJsonPath),
                new TypeReference<List<Map<String, Object>>>() {});

        List<PrivacyApiRule> rules = new ArrayList<>();
        for (Map<String, Object> pkg : apiPackages) {
            String namespace = (String) pkg.get("systemPackage");
            List<Map<String, Object>> apis = (List<Map<String, Object>>) pkg.get("privacyApis");
            if (apis == null) continue;

            for (Map<String, Object> api : apis) {
                PrivacyApiRule rule = new PrivacyApiRule();
                rule.namespace = namespace;
                rule.method = (String) api.get("method");
                rule.apiPackage = (String) api.get("apiPackage");
                rule.profilingCategory = (String) api.get("profilingCategory");
                rule.dataDirection = (String) api.get("dataDirection");
                if (rule.method != null && !rule.method.isEmpty()) {
                    rules.add(rule);
                }
            }
        }
        return rules;
    }

    // ======================================================
    // Report Output
    // ======================================================

    static void writeReport(List<BaselineReport> reports, String outputPath) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);

            Map<String, Object> output = new LinkedHashMap<>();
            output.put("experiment", "Decision Experiment 1: Official Metadata Baseline");
            output.put("timestamp", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));

            List<Map<String, Object>> hapReports = new ArrayList<>();
            for (BaselineReport r : reports) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("hapName", r.hapName);
                m.put("totalCallSites", r.totalCallSites);
                m.put("directUnique", r.directUnique);
                m.put("indirectAmbiguous", r.indirectAmbiguous);
                m.put("unresolved", r.unresolved);
                m.put("ambiguousWithPrivacyConflict", r.ambiguousWithPrivacyConflict);
                m.put("ambiguousNoPrivacyConflict", r.ambiguousNoPrivacyConflict);
                m.put("candidateCountDistribution", r.candidateCountDistribution);
                hapReports.add(m);
            }
            output.put("reports", hapReports);

            // Detailed ambiguous sites
            List<Map<String, Object>> ambigDetails = new ArrayList<>();
            for (BaselineReport r : reports) {
                for (CallSiteClassification c : r.details) {
                    if ("INDIRECT_AMBIGUOUS".equals(c.classification)) {
                        Map<String, Object> d = new LinkedHashMap<>();
                        d.put("hap", c.hapName);
                        d.put("method", c.methodName);
                        d.put("fullApiName", c.fullApiName);
                        d.put("candidateCount", c.candidateCount);
                        d.put("namespaces", c.matchingNamespaces);
                        d.put("categories", c.matchingCategories);
                        d.put("hasPrivacyConflict", c.hasPrivacyConflict);
                        ambigDetails.add(d);
                    }
                }
            }
            output.put("ambiguousSites", ambigDetails);

            mapper.writeValue(new File(outputPath), output);
        } catch (Exception e) {
            System.out.println("[ERROR] Failed to write report: " + e.getMessage());
        }
    }
}
