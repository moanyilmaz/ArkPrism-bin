package com.huawei.hisec;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.huawei.hianalyzer.analysis.Stage;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.base.HiFunction;
import com.huawei.hianalyzer.analysis.graph.callgraph.CallGraph;
import com.huawei.hianalyzer.analysis.graph.cfg.BasicBlock;
import com.huawei.hianalyzer.analysis.graph.cfg.BlockGraph;
import com.huawei.hianalyzer.analysis.graph.cfg.StmtGraph;
import com.huawei.hianalyzer.analysis.graph.callgraph.pta.andersen.Andersen;
import com.huawei.hianalyzer.dataflow.ifds.analysis.taint.AliasManager;
import com.huawei.hianalyzer.frontend.metainterface.SourceLang;
import com.huawei.hianalyzer.ir.bodytransformer.ssa.SSA;
import com.huawei.hianalyzer.ir.bodytransformer.utils.DominantTree;
import com.huawei.hianalyzer.ir.stmt.CallStmt;
import com.huawei.hianalyzer.ir.stmt.Stmt;
import com.huawei.hianalyzer.ir.value.ArrayElement;
import com.huawei.hianalyzer.ir.value.Local;
import com.huawei.hianalyzer.ir.value.reference.FieldRef;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

/**
 * ArkTS / ABC Sensitive API Scanner.
 *
 * Responsibilities:
 * 1. Scan all .abc files in extracted hap directory
 * 2. Identify sensitive ArkTS APIs based on privacy_apis.json
 * 3. Build call chains for ArkTS API hits
 * 4. Perform forward data flow analysis on ArkTS hits
 * 5. Output UnifiedPrivacyReport.ApiUsage and UnifiedPrivacyReport.CallChainReport
 *
 * Note:
 * Native/.so hits are handled by SoVulnerabilityScanner
 */
public class PreciseSensitiveApiScanner {

    private static final boolean SYSTEM_ONLY_MODE = false;
    /**
     * Enable SSA transformation before scanning.
     * SSA converts phi nodes and copies into explicit SSA form, enabling more accurate
     * def-use analysis. It can be expensive for large codebases.
     * Default: false (disabled for better performance)
     */
    private static final boolean ENABLE_SSA = false;

    // ======================================================
    // 1. JSON Rule Models
    // ======================================================

    public static class PrivacyPackageInfo {
        public String systemPackage;
        public List<PrivacyApiRule> privacyApis;
    }

    public static class PrivacyApiRule {
        public Boolean directCall;
        public String namespace;
        public String method;
        public String permission;

        // Compatible with source-code rule fields
        public String profilingCategory;
        public String category;
        public String apiPackage;
        public String dataDirection;  // "source" | "sink" | "both" | "excluded"
    }

    public static class PrivacyApiRuleWithPkg {
        public String systemPackage;
        public PrivacyApiRule rule;
    }

    // ======================================================
    // 2. Hit Result Models
    // ======================================================

    public static class SensitiveApiHit {
        public String layer;
        public String category;
        public String sourceKind;
        public String systemPackage;
        public String namespace;
        public String method;
        public String permission;
        public String profilingCategory;
        public String dataDirection;  // "source" | "sink" | "both"
        public String matchedFullName;
        public String stmtClass;
        public String stmtText;
        public String file;
        public String function;
        public int stmtIndex = -1;
        public String confidence = "high";  // high / medium / low, default high
        public transient Stmt stmtObj;
    }

    /**
     * Provenance record: tracks which SensitiveApiHit produced each deduplicated ApiUsage,
     * and which Stmt object is the IR-level source for call chain construction.
     *
     * This eliminates the need for the fragile string-key cross-matching between
     * the dedup loop and the sourceStmtToApiUsageIndex mapping loop. Instead of
     * reconstructing the Hit→Usage relationship via string comparison, we maintain
     * a direct object reference from each deduplicated usage back to its originating hit.
     */
    public static class ApiUsageProvenance {
        public final SensitiveApiHit originatingHit;
        public final Stmt sourceStmt; // May be null if hit has no Stmt object

        public ApiUsageProvenance(SensitiveApiHit hit) {
            this.originatingHit = hit;
            this.sourceStmt = (hit != null && hit.stmtObj != null) ? hit.stmtObj : null;
        }
    }

    public static class ResolvedNameInfo {
        public String original;
        public String sourcePrefix;
        public String rawBody;
        public String rootQualifier;
        public List<String> pathTokens = new ArrayList<>();
        public String lastToken;
        public List<String> prefixTokens = new ArrayList<>();
        public boolean valid;
    }

    public static class ArkTsScanResult {
        public List<UnifiedPrivacyReport.ApiUsage> arktsApiUsages = new ArrayList<>();
        public List<UnifiedPrivacyReport.CallChainReport> callChains = new ArrayList<>();
        public int analyzedAbcCount = 0;
        public List<String> warnings = new ArrayList<>();

        // Parser statistics
        public int v1SuccessCount = 0;
    }

    // ======================================================
    // 3. Main Entry: Scan One HAP Directory
    // ======================================================

    public ArkTsScanResult scanDirectory(String targetDirectory, String ruleJsonPath) {
        return scanDirectory(new File(targetDirectory), new File(ruleJsonPath));
    }

    public ArkTsScanResult scanDirectory(File targetDirectory, File ruleJsonFile) {
        ArkTsScanResult result = new ArkTsScanResult();

        Logger.log("======================================================");
        Logger.log("[*] ArkTS ABC Sensitive API Scanner");
        Logger.log("======================================================");
        Logger.log("[*] targetDirectory = " + safePath(targetDirectory));
        Logger.log("[*] ruleJsonFile = " + safePath(ruleJsonFile));

        if (targetDirectory == null || !targetDirectory.exists()) {
            result.warnings.add("ArkTS scan skipped: target directory does not exist.");
            return result;
        }

        if (ruleJsonFile == null || !ruleJsonFile.exists()) {
            result.warnings.add("ArkTS scan skipped: rule json file does not exist.");
            return result;
        }

        List<File> abcFiles = new ArrayList<>();
        try {
            collectAbcFiles(targetDirectory, abcFiles);
        } catch (IOException e) {
            result.warnings.add("Failed to collect abc files: " + e.getMessage());
            return result;
        }

        result.analyzedAbcCount = abcFiles.size();

        if (abcFiles.isEmpty()) {
            result.warnings.add("No abc files found in: " + targetDirectory.getAbsolutePath());
            return result;
        }

        List<PrivacyPackageInfo> packageInfos;
        try {
            packageInfos = loadPrivacyApis(ruleJsonFile.getAbsolutePath());
        } catch (IOException e) {
            result.warnings.add("Failed to load privacy rule json: " + e.getMessage());
            return result;
        }

        List<PrivacyApiRuleWithPkg> allRules = flattenRules(packageInfos);

        // Filter out excluded rules (dataDirection="excluded") — they are not privacy-sensitive
        long excludedCount = allRules.stream()
                .filter(r -> "excluded".equalsIgnoreCase(r.rule.dataDirection))
                .count();
        if (excludedCount > 0) {
            Logger.log("[*] Excluding " + excludedCount + " APIs with dataDirection=excluded");
        }

        List<PrivacyApiRuleWithPkg> directRules = allRules.stream()
                .filter(r -> Boolean.TRUE.equals(r.rule.directCall))
                .filter(r -> !"excluded".equalsIgnoreCase(r.rule.dataDirection))
                .collect(Collectors.toList());

        List<PrivacyApiRuleWithPkg> indirectRules = allRules.stream()
                .filter(r -> Boolean.FALSE.equals(r.rule.directCall))
                .filter(r -> !"excluded".equalsIgnoreCase(r.rule.dataDirection))
                .collect(Collectors.toList());

        List<PrivacyApiRuleWithPkg> constantRules = allRules.stream()
                .filter(r -> r.rule.directCall == null)
                .filter(r -> !"excluded".equalsIgnoreCase(r.rule.dataDirection))
                .collect(Collectors.toList());

        int nextApiUsageIndex = 0;
        int totalV1Success = 0;

        for (File abcFile : abcFiles) {
            Logger.log("\n######################################################");
            Logger.log("[*] Analyzing ABC: " + abcFile.getAbsolutePath());

            HiFile hiFile = parseAbcWithV1(abcFile, result.warnings);
            if (hiFile == null) {
                Logger.log("[-] V1 parser failed, skipping.");
                continue;
            }
            totalV1Success++;

            transformWithSSA(hiFile);

            // Build call graph BEFORE scanning so Andersen PTA is available
            // for namespace inference during indirect call matching.
            // The same CG will be reused for chain extraction in buildCallChainsForFile.
            CallGraph cg = null;
            try {
                Logger.log("[*] Building call graph with ANDERSEN for scanning...");
                cg = Stage.createCallGraph(hiFile, CallGraph.CGBuildMethod.ANDERSEN, true);
            } catch (Throwable t) {
                String msg = "Call graph construction failed for " + abcFile.getAbsolutePath() + ": " + t.getMessage();
                result.warnings.add(msg);
                Logger.error("[-] " + msg);
            }

            List<SensitiveApiHit> hits = scanHiFile(
                    hiFile,
                    abcFile.getName(),
                    directRules,
                    indirectRules,
                    constantRules,
                    cg
            );
            Logger.log("    [*] V1 raw hits: " + hits.size());

            if (hits.isEmpty()) {
                Logger.log("[-] No sensitive API hits in current ABC.");
                continue;
            }

            Logger.log("[+] Current ABC sensitive API hits: " + hits.size());

            // Deduplicate ApiUsage objects with direct provenance tracking.
            // Each deduplicated usage retains a reference to its originating hit,
            // eliminating the need for the fragile string-key cross-matching that
            // previously caused ~37.7% of API usages to lose their call chains.
            List<UnifiedPrivacyReport.ApiUsage> dedupedUsages = new ArrayList<>();
            Map<UnifiedPrivacyReport.ApiUsage, ApiUsageProvenance> usageToProvenance = new LinkedHashMap<>();
            Set<String> seenUsageKeys = new HashSet<>();
            Set<Stmt> sinkStmts = new LinkedHashSet<>();

            for (SensitiveApiHit hit : hits) {
                UnifiedPrivacyReport.ApiUsage usage = convertArkTsHitToApiUsage(hit, targetDirectory, abcFile);

                // Create dedup key from usage fields
                String usageKey = (usage.code != null ? usage.code : "")
                        + "|" + (usage.declaringMethod != null ? usage.declaringMethod : "")
                        + "|" + (usage.namespace != null ? usage.namespace : "")
                        + "|" + (usage.method != null ? usage.method : "")
                        + "|" + (usage.sourceKind != null ? usage.sourceKind : "")
                        + "|" + (usage.category != null ? usage.category : "");

                if (seenUsageKeys.add(usageKey)) {
                    dedupedUsages.add(usage);
                    usageToProvenance.put(usage, new ApiUsageProvenance(hit));

                    // Any hit with a Stmt object participates in call chain construction,
                    // regardless of layer (BODY_HIT or CHAIN_EVIDENCE). Previously,
                    // only BODY_HIT hits were included, causing FIELD_MAP indirect-invoke
                    // hits to be orphaned from call chain construction.
                    if (hit.stmtObj != null) {
                        sinkStmts.add(hit.stmtObj);
                    }
                }
            }

            // Record the starting index for this file's usages in the global list
            int dedupStartIndex = nextApiUsageIndex;

            // Add deduplicated usages to the result, maintaining index order
            for (UnifiedPrivacyReport.ApiUsage usage : dedupedUsages) {
                result.arktsApiUsages.add(usage);
            }

            // Advance the global index counter
            nextApiUsageIndex += dedupedUsages.size();

            // Build call chains for this file.
            // Note: sinkStmts may be empty if all hits have no Stmt objects
            // (e.g., pure CHAIN_EVIDENCE without stmtObj). In that case,
            // buildCallChainsForFile will generate fallback chains for all usages.
            buildCallChainsForFile(
                    hiFile,
                    abcFile,
                    sinkStmts,
                    usageToProvenance,
                    dedupStartIndex,
                    ruleJsonFile,
                    result.callChains,
                    result.warnings,
                    cg
            );
        }

        result.v1SuccessCount = totalV1Success;

        Logger.log("[+] V1 parser success count: " + totalV1Success);
        Logger.log("[+] ArkTS ABC scan complete, API hits: " + result.arktsApiUsages.size());
        Logger.log("[+] ArkTS call chains: " + result.callChains.size());

        return result;
    }

    // ======================================================
    // 4.1 Dual-parser support
    // ======================================================

    /**
     * Parse an .abc file with ARKTSV1.
     * Returns the parsed HiFile, or null if parsing fails.
     */
    private HiFile parseAbcWithV1(File abcFile, List<String> warnings) {
        try {
            HiFile hiFile = Stage.createHiFile(abcFile.getAbsolutePath(), SourceLang.ARKTSV1);
            if (hiFile != null) {
                int funcCount = hiFile.getHiFunctions() == null ? 0 : hiFile.getHiFunctions().size();
                Logger.log("    [+] ARKTSV1: success, functions=" + funcCount);
                return hiFile;
            } else {
                Logger.log("    [-] ARKTSV1: returned null");
                return null;
            }
        } catch (Throwable t) {
            String msg = t.getMessage();
            Logger.log("    [-] ARKTSV1: " + (msg == null || msg.isBlank() ? t.getClass().getSimpleName() : msg));
            return null;
        }
    }

    // ======================================================
    // 4. Build Call Chains and Data Flow for One ABC
    // ======================================================

    /**
     * Builds call chains and data flow analysis results for all API usages in a single ABC file.
     *
     * Uses provenance-based Stmt→apiUsageIndex mapping (one-to-many) instead of the
     * previous fragile string-key matching. Every API usage is guaranteed to receive
     * at least a fallback chain, even if no call graph path is found or the usage
     * has no Stmt object.
     *
     * @param hiFile              Parsed HiFile for this ABC
     * @param abcFile             The ABC file being analyzed
     * @param sinkStmts           Set of Stmt objects that are sensitive API call sites
     * @param usageToProvenance   Direct provenance map from each deduplicated ApiUsage to its originating hit
     * @param dedupStartIndex     The global apiUsageIndex offset for this file's usages
     * @param ruleJsonFile        Path to privacy_apis.json for data flow analysis
     * @param outputChains        Output list to append CallChainReport objects to
     * @param warnings            Output list to append warning messages to
     */
    private void buildCallChainsForFile(
            HiFile hiFile,
            File abcFile,
            Set<Stmt> sinkStmts,
            Map<UnifiedPrivacyReport.ApiUsage, ApiUsageProvenance> usageToProvenance,
            int dedupStartIndex,
            File ruleJsonFile,
            List<UnifiedPrivacyReport.CallChainReport> outputChains,
            List<String> warnings,
            CallGraph cg
    ) {
        // ── Build one-to-many Stmt → apiUsageIndex mapping from provenance ──
        // A single Stmt can map to multiple apiUsageIndex values when:
        // 1. The same call site matches both direct and indirect rules
        // 2. The same Stmt appears in both stmtApiMap and stmtFieldMap
        Map<Stmt, List<Integer>> stmtToUsageIndices = new LinkedHashMap<>();
        List<UnifiedPrivacyReport.ApiUsage> provenanceUsages = new ArrayList<>(usageToProvenance.keySet());

        for (int i = 0; i < provenanceUsages.size(); i++) {
            ApiUsageProvenance prov = usageToProvenance.get(provenanceUsages.get(i));
            if (prov != null && prov.sourceStmt != null) {
                stmtToUsageIndices
                        .computeIfAbsent(prov.sourceStmt, k -> new ArrayList<>())
                        .add(dedupStartIndex + i);
            }
        }

        // ── Call graph is built in scanDirectory() before scanHiFile() ──
        // and passed here for reuse. This avoids building the CG twice and
        // ensures the CG state is consistent with what PTA used during scanning.

        // ── Extract call chains with per-stmt attribution ──
        List<CallGraphExplorer.CallChain> chains = Collections.emptyList();
        if (cg != null && !sinkStmts.isEmpty()) {
            try {
                Map<Stmt, HiFunction> sinkToFunctionMap =
                        CallGraphExplorer.buildSinkToFunctionMap(sinkStmts);
                chains = CallGraphExplorer.extractPrivacyCallChainsWithStmtAttribution(
                        hiFile, cg, sinkStmts, sinkToFunctionMap
                );
            } catch (Throwable t) {
                String msg = "Call chain extraction failed for " + abcFile.getAbsolutePath() + ": " + t.getMessage();
                warnings.add(msg);
                Logger.error("[-] " + msg);
            }
        }

        Logger.log("[+] Call chain extraction complete: " + chains.size()
                + " (sinkStmts=" + sinkStmts.size()
                + ", stmtToUsageIndices entries=" + stmtToUsageIndices.size() + ")");

        // ── Data flow analysis ──
        Map<Stmt, List<CallStmt>> dataFlowResults = new HashMap<>();
        if (cg != null) {
            try {
                Logger.log("[*] Attempting forward data flow analysis...");
                dataFlowResults = DataFlowExplorer.findDataSinks(hiFile, cg, sinkStmts,
                        ruleJsonFile != null ? ruleJsonFile.getAbsolutePath() : null);
            } catch (Throwable t) {
                String msg = "Data flow analysis skipped for " + abcFile.getAbsolutePath() + ": " + t.getMessage();
                warnings.add(msg);
                Logger.error("[-] " + msg);
            }
        }

        // ── Build per-stmt chain lookup ──
        Map<Stmt, List<CallGraphExplorer.CallChain>> stmtToChains = new LinkedHashMap<>();
        for (CallGraphExplorer.CallChain chain : chains) {
            if (chain.sinkStmt != null) {
                stmtToChains.computeIfAbsent(chain.sinkStmt, k -> new ArrayList<>()).add(chain);
            }
        }

        // ── Track which apiUsageIndex values have received at least one chain ──
        Set<Integer> coveredIndices = new HashSet<>();

        // ── Generate CallChainReports for each Stmt that has apiUsageIndex mapping ──
        for (Map.Entry<Stmt, List<Integer>> entry : stmtToUsageIndices.entrySet()) {
            Stmt sourceStmt = entry.getKey();
            List<Integer> indices = entry.getValue();
            List<CallGraphExplorer.CallChain> chainsForStmt =
                    stmtToChains.getOrDefault(sourceStmt, Collections.emptyList());

            HiFunction sourceFunc = safeGetHiFunction(sourceStmt);

            for (int apiUsageIndex : indices) {
                if (chainsForStmt.isEmpty()) {
                    // No call chains found from entry — generate fallback
                    UnifiedPrivacyReport.CallChainReport fallback = buildFallbackChainReport(
                            apiUsageIndex,
                            abcFile,
                            sourceStmt,
                            sourceFunc,
                            dataFlowResults.getOrDefault(sourceStmt, new ArrayList<>()),
                            hiFile
                    );
                    outputChains.add(fallback);
                } else {
                    // Generate one CallChainReport per discovered call path
                    for (CallGraphExplorer.CallChain chain : chainsForStmt) {
                        UnifiedPrivacyReport.CallChainReport reportChain = convertCallChain(
                                apiUsageIndex,
                                abcFile,
                                sourceStmt,
                                chain,
                                dataFlowResults.getOrDefault(sourceStmt, new ArrayList<>()),
                                hiFile
                        );
                        outputChains.add(reportChain);
                    }
                }
                coveredIndices.add(apiUsageIndex);
            }
        }

        // ── Generate fallback chains for usages with NO Stmt object ──
        // These are API usages whose originating hit had stmtObj == null
        // (typically CHAIN_EVIDENCE hits without a recoverable Stmt reference,
        // or property-access patterns that don't map to a call-site Stmt).
        for (int i = 0; i < provenanceUsages.size(); i++) {
            int apiUsageIndex = dedupStartIndex + i;
            if (coveredIndices.contains(apiUsageIndex)) {
                continue; // Already has chain(s)
            }

            UnifiedPrivacyReport.ApiUsage usage = provenanceUsages.get(i);
            ApiUsageProvenance prov = usageToProvenance.get(usage);

            UnifiedPrivacyReport.CallChainReport fallback =
                    buildFallbackChainForUsage(apiUsageIndex, usage, prov, abcFile, hiFile);
            outputChains.add(fallback);
            Logger.log("[+] Generated fallback chain for usage #" + apiUsageIndex
                    + " (no Stmt: " + (usage.namespace != null ? usage.namespace : "")
                    + "." + (usage.method != null ? usage.method : "") + ")");
        }
    }

    private UnifiedPrivacyReport.CallChainReport buildFallbackChainReport(
            int apiUsageIndex,
            File abcFile,
            Stmt sourceStmt,
            HiFunction sourceFunc,
            List<CallStmt> dataSinks,
            HiFile hiFile
    ) {
        UnifiedPrivacyReport.CallChainReport report = new UnifiedPrivacyReport.CallChainReport();
        report.apiUsageIndex = apiUsageIndex;

        report.entryMethod = new UnifiedPrivacyReport.EntryMethod();
        report.entryMethod.name = safeFunctionName(sourceFunc);
        report.entryMethod.type = inferEntryMethodType(sourceFunc);
        report.entryMethod.file = abcFile.getName();
        report.entryMethod.line = -1;

        UnifiedPrivacyReport.SourceSnippet snippet = buildSourceSnippet(sourceFunc, abcFile.getName());
        report.sourceSnippets.add(snippet);

        report.dataSinks.addAll(convertDataSinks(dataSinks, hiFile, abcFile.getName()));

        report.semanticContext = buildSemanticContext(
                Collections.singletonList(sourceFunc),
                sourceStmt,
                report.dataSinks,
                abcFile.getName()
        );

        return report;
    }

    /**
     * Builds a minimal fallback chain for an API usage that has no Stmt object.
     * This occurs when the originating hit had stmtObj == null (e.g., CHAIN_EVIDENCE
     * hits without a recoverable Stmt reference, or property-access patterns that
     * don't map to a call-site Stmt).
     *
     * The fallback chain uses the usage's declaringMethod as the entry point and
     * provides a semantic context describing the API reference. While it lacks
     * the full call path and source snippets, it ensures every API usage has at
     * least one CallChainReport, guaranteeing complete apiUsageIndex coverage.
     */
    private UnifiedPrivacyReport.CallChainReport buildFallbackChainForUsage(
            int apiUsageIndex,
            UnifiedPrivacyReport.ApiUsage usage,
            ApiUsageProvenance prov,
            File abcFile,
            HiFile hiFile
    ) {
        UnifiedPrivacyReport.CallChainReport report = new UnifiedPrivacyReport.CallChainReport();
        report.apiUsageIndex = apiUsageIndex;

        report.entryMethod = new UnifiedPrivacyReport.EntryMethod();
        report.entryMethod.name = usage.declaringMethod != null ? usage.declaringMethod : "<unknown>";
        report.entryMethod.type = inferEntryMethodTypeByName(usage.declaringMethod);
        report.entryMethod.file = abcFile.getName();
        report.entryMethod.line = -1;

        // Attempt to find the HiFunction for source snippet extraction
        if (usage.declaringMethod != null && hiFile != null) {
            HiFunction func = findFunctionByName(hiFile, usage.declaringMethod);
            if (func != null) {
                report.sourceSnippets.add(buildSourceSnippet(func, abcFile.getName()));
            }
        }

        report.semanticContext = new UnifiedPrivacyReport.SemanticContext();
        report.semanticContext.pageName = inferPageName(abcFile.getName());
        report.semanticContext.componentClass = inferComponentClass(usage.declaringMethod);
        report.semanticContext.semanticAnchor = usage.declaringMethod;

        String apiLabel = (usage.namespace != null ? usage.namespace : "")
                + "." + (usage.method != null ? usage.method : "sensitive API");
        report.semanticContext.simplifiedChain =
                simplifyFunctionName(usage.declaringMethod) + "() -> " + apiLabel;
        report.semanticContext.purposeHint = "In " + abcFile.getName()
                + ", function " + simplifyFunctionName(usage.declaringMethod)
                + "() references " + apiLabel;

        return report;
    }

    /**
     * Infers entry method type from function name string alone (without HiFunction object).
     * Used by buildFallbackChainForUsage when no Stmt/HiFunction is available.
     */
    private String inferEntryMethodTypeByName(String functionName) {
        if (functionName == null) {
            return "method";
        }
        String lowerName = functionName.toLowerCase(Locale.ROOT);

        if (lowerName.contains(".build") || lowerName.contains("abouttoappear") ||
            lowerName.contains("abouttodisappear") || lowerName.contains("onpageshow") ||
            lowerName.contains("onpagehide") || lowerName.contains("onbackpress") ||
            lowerName.contains("onready") || lowerName.contains("ondisposed") ||
            lowerName.contains("oninit") || lowerName.contains("onstart") ||
            lowerName.contains("onstop") || lowerName.contains("onactive") ||
            lowerName.contains("oninactive") || lowerName.contains("onforeground") ||
            lowerName.contains("onbackground")) {
            return "component_lifecycle";
        }

        if (lowerName.contains("onabilitycreate") || lowerName.contains("onabilitydestroy") ||
            lowerName.contains("onabilityforeground") || lowerName.contains("onabilitybackground") ||
            lowerName.contains("onwindowstagecreate") || lowerName.contains("onwindowstagedestroy") ||
            lowerName.contains("oncontinue") || lowerName.contains("onnewwant") ||
            lowerName.contains("ondump") || lowerName.contains("onrequest")) {
            return "ability_lifecycle";
        }

        if (functionName.endsWith("Component") || functionName.endsWith("Page") ||
            functionName.endsWith("View") || functionName.endsWith("Builder") ||
            functionName.endsWith("Element") || functionName.endsWith("Item")) {
            return "ui_component";
        }

        if (lowerName.contains("onclick") || lowerName.contains("onchange") ||
            lowerName.contains("oninput") || lowerName.contains("onsubmit") ||
            lowerName.contains("ontouchstart") || lowerName.contains("ontouchmove") ||
            lowerName.contains("ontouchend") || lowerName.contains("onscroll") ||
            lowerName.contains("onswipe") || lowerName.contains("onlongpress") ||
            lowerName.contains("%am") || lowerName.contains("%o_click") ||
            lowerName.contains("handler_click") || lowerName.contains("handler_change")) {
            return "event_handler";
        }

        if (lowerName.contains("callback") || lowerName.contains("then(") ||
            lowerName.contains("catch(") || lowerName.contains("%resolve") ||
            lowerName.contains("%reject") || lowerName.contains("_callback_") ||
            lowerName.contains("_success") || lowerName.contains("_fail") ||
            lowerName.contains("_complete")) {
            return "async_callback";
        }

        if (functionName.equals("func_main_0") || functionName.startsWith("func_")) {
            return "entry_point";
        }

        return "method";
    }

    /**
     * Finds a HiFunction by name in the HiFile.
     * Used by buildFallbackChainForUsage to extract source snippets when
     * we have a function name but no Stmt reference.
     */
    private HiFunction findFunctionByName(HiFile hiFile, String functionName) {
        if (hiFile == null || functionName == null) {
            return null;
        }
        try {
            for (HiFunction func : hiFile.getHiFunctions()) {
                if (func != null && functionName.equals(func.getName())) {
                    return func;
                }
            }
        } catch (Throwable t) {
            // Fall through
        }
        return null;
    }

    private UnifiedPrivacyReport.CallChainReport convertCallChain(
            int apiUsageIndex,
            File abcFile,
            Stmt sourceStmt,
            CallGraphExplorer.CallChain chain,
            List<CallStmt> dataSinks,
            HiFile hiFile
    ) {
        UnifiedPrivacyReport.CallChainReport report = new UnifiedPrivacyReport.CallChainReport();
        report.apiUsageIndex = apiUsageIndex;

        report.entryMethod = new UnifiedPrivacyReport.EntryMethod();
        report.entryMethod.name = safeFunctionName(chain.rootNode);
        report.entryMethod.type = inferEntryMethodType(chain.rootNode);
        report.entryMethod.file = abcFile.getName();
        report.entryMethod.line = -1;

        List<HiFunction> path = chain.path == null ? new ArrayList<>() : chain.path;

        for (int i = 0; i + 1 < path.size(); i++) {
            HiFunction caller = path.get(i);
            HiFunction callee = path.get(i + 1);

            UnifiedPrivacyReport.CallEdge edge = new UnifiedPrivacyReport.CallEdge();
            edge.caller = safeFunctionName(caller);
            edge.callee = safeFunctionName(callee);
            edge.callType = inferCallType(caller, callee);
            edge.resolvedCallerName = simplifyFunctionName(edge.caller);
            edge.resolvedCalleeName = simplifyFunctionName(edge.callee);
            report.chain.add(edge);
        }

        for (HiFunction func : path) {
            report.sourceSnippets.add(buildSourceSnippet(func, abcFile.getName()));
        }

        report.dataSinks.addAll(convertDataSinks(dataSinks, hiFile, abcFile.getName()));

        report.semanticContext = buildSemanticContext(
                path,
                sourceStmt,
                report.dataSinks,
                abcFile.getName()
        );

        return report;
    }

    // ======================================================
    // 5. ArkTS hit -> Unified ApiUsage
    // ======================================================

    private UnifiedPrivacyReport.ApiUsage convertArkTsHitToApiUsage(
            SensitiveApiHit hit,
            File projectDirectory,
            File abcFile
    ) {
        UnifiedPrivacyReport.ApiUsage usage = new UnifiedPrivacyReport.ApiUsage();

        usage.sourceLayer = "ArkTS";
        usage.sourceKind = hit.sourceKind;
        usage.category = hit.category;
        usage.apiPackage = normalizeApiPackage(hit.systemPackage);
        usage.namespace = hit.namespace;
        usage.method = hit.method;
        usage.args = extractArgsFromStmt(hit.stmtText);
        usage.code = hit.stmtText;
        usage.file = hit.file != null ? hit.file : abcFile.getName();
        usage.declaringMethod = hit.function;
        usage.permission = hit.permission;
        usage.profilingCategory = hit.profilingCategory != null
                ? hit.profilingCategory
                : inferArkTsProfilingCategory(hit.namespace, hit.method, hit.systemPackage);
        usage.dataDirection = hit.dataDirection;

        usage.prototype = null;
        usage.symbol = null;
        usage.arch = null;
        usage.soName = null;
        usage.matchType = null;
        usage.risk = inferArkTsRisk(usage.profilingCategory, usage.permission);
        usage.evidence = null;

        // Propagate confidence from CFG reachability check (highest priority)
        if (hit.confidence != null) {
            usage.confidence = hit.confidence;
        }

        // @import APIs (third-party SDK) get low confidence, but don't override CFG result
        String sourcePrefix = getSourcePrefix(hit.matchedFullName);
        if ("@import".equals(sourcePrefix)) {
            if (!"low".equals(usage.confidence)) {
                usage.confidence = "low";
            }
            usage.category = "(@import) " + usage.category;
        } else if (hit.confidence == null) {
            // Only set default high if neither CFG nor @import set confidence
            usage.confidence = "high";
        }

        return usage;
    }

    // ======================================================
    // 6. Original scanHiFile and Matching Logic
    // ======================================================

    private List<SensitiveApiHit> scanHiFile(
            HiFile hiFile,
            String fileName,
            List<PrivacyApiRuleWithPkg> directRules,
            List<PrivacyApiRuleWithPkg> indirectRules,
            List<PrivacyApiRuleWithPkg> constantRules,
            CallGraph cg
    ) {
        List<SensitiveApiHit> results = new ArrayList<>();

        // Extract Andersen PTA from call graph for namespace inference
        Andersen andersen = null;
        if (cg != null && cg.getPta() instanceof Andersen) {
            andersen = (Andersen) cg.getPta();
        }

        Map<Stmt, String> stmtApiMap = safeGetAllStmtApiNameMap(hiFile);
        Map<Stmt, String> stmtFieldMap = safeGetAllStmtFieldNameMap(hiFile);

        // Track Stmts that already produced an API_MAP hit to prevent cross-map
        // duplication. When the same Stmt appears in both stmtApiMap and stmtFieldMap,
        // the API_MAP hit is always more informative (full call signature with arguments),
        // so the FIELD_MAP hit is redundant and should be suppressed.
        Set<Stmt> stmtsWithApiMapHit = new HashSet<>();

        // Also track (function, namespace, method) triples from API_MAP hits.
        // Since API_MAP and FIELD_MAP use different Stmt objects for the same
        // call site, Stmt-identity dedup alone is insufficient. When a FIELD_MAP
        // entry with the SSA phi pattern (vN = vN.<method>) matches the same
        // (function, namespace, method) as an API_MAP entry, it's redundant.
        Set<String> apiMapFunctionMethodKeys = new HashSet<>();

        for (Map.Entry<Stmt, String> entry : stmtApiMap.entrySet()) {
            Stmt stmt = entry.getKey();
            String fullApiName = normalizeFullName(entry.getValue());
            String stmtText = safe(stmt);

            if (stmt == null || fullApiName == null || fullApiName.isEmpty()) {
                continue;
            }

            ResolvedNameInfo info = parseResolvedName(fullApiName);
            if (!isAcceptedResolvedName(info)) {
                continue;
            }

            HiFunction func = safeGetHiFunction(stmt);
            String functionName = safeFunctionName(func);

            SensitiveApiHit directHit = matchDirectCall(
                    stmt, info, fileName, functionName, directRules, "BODY_HIT", "API_MAP"
            );
            if (directHit != null) {
                results.add(directHit);
                stmtsWithApiMapHit.add(stmt);
                apiMapFunctionMethodKeys.add(functionName + "|" + directHit.namespace + "|" + directHit.method);
                continue;
            }

            SensitiveApiHit indirectHit = matchIndirectCall(
                    stmt, info, fileName, functionName, indirectRules, "BODY_HIT", "API_MAP", andersen
            );
            if (indirectHit != null) {
                results.add(indirectHit);
                stmtsWithApiMapHit.add(stmt);
                apiMapFunctionMethodKeys.add(functionName + "|" + indirectHit.namespace + "|" + indirectHit.method);
            }
        }

        for (Map.Entry<Stmt, String> entry : stmtFieldMap.entrySet()) {
            Stmt stmt = entry.getKey();
            String fullFieldName = normalizeFullName(entry.getValue());

            if (stmt == null || fullFieldName == null || fullFieldName.isEmpty()) {
                continue;
            }

            // Cross-map deduplication: if this Stmt already produced an API_MAP hit,
            // skip it in the FIELD_MAP loop. The API_MAP hit contains the full call
            // signature (e.g., "v10 = VirtualCall: v2.<uploadFile>(v4, v5)"), while
            // the FIELD_MAP hit only has the property reference (e.g., "v10 = v10.<uploadFile>").
            // Keeping both would double-count the same call site.
            if (stmtsWithApiMapHit.contains(stmt)) {
                continue;
            }

            String stmtText = safe(stmt);

            // SSA phi/copy pattern: "vN = vN.<method>" where LHS == RHS variable.
            // In the FIELD_MAP, this pattern arises for two reasons:
            //   1. Redundant: The API_MAP already captured the full call (e.g.,
            //      "v9 = VirtualCall: v1.<request>(v4, v2, v5)"), and the FIELD_MAP
            //      has the property reference form ("v9 = v9.<request>"). Skipping
            //      these avoids double-counting the same call site.
            //   2. Legitimate: Property accesses like "v10 = v10.<brand>" for
            //      constant APIs (deviceInfo.brand) have no corresponding API_MAP entry,
            //      so the FIELD_MAP is the only source. These must NOT be filtered.
            //
            // Strategy: When isSsaPhiNode matches, still try matchPrivacyConstant
            // (which handles constant/property APIs), but skip matchDirectCall and
            // matchIndirectCall (which would produce redundant call-site entries).
            boolean isSsaPattern = isSsaPhiNode(stmtText);

            ResolvedNameInfo info = parseResolvedName(fullFieldName);
            if (!isAcceptedResolvedName(info)) {
                continue;
            }

            HiFunction func = safeGetHiFunction(stmt);
            String functionName = safeFunctionName(func);

            // Always try constant/property matching (directCall=null rules)
            SensitiveApiHit fieldHit = matchPrivacyConstant(
                    stmt, info, fileName, functionName, constantRules, "BODY_HIT", "FIELD_MAP"
            );
            if (fieldHit != null) {
                results.add(fieldHit);
                continue;
            }

            // For SSA phi patterns (vN = vN.<method>), skip matchDirectCall because
            // the API_MAP already has the full call signature. For matchIndirectCall
            // (directCall=false rules like deviceInfo.ODID), only add the hit if
            // the API_MAP doesn't already have an entry for the same
            // (function, namespace, method) — otherwise it's a redundant duplicate.
            if (isSsaPattern) {
                SensitiveApiHit indirectChain = matchIndirectCall(
                        stmt, info, fileName, functionName, indirectRules, "CHAIN_EVIDENCE", "FIELD_MAP", andersen
                );
                if (indirectChain != null) {
                    String fmKey = functionName + "|" + indirectChain.namespace + "|" + indirectChain.method;
                    if (!apiMapFunctionMethodKeys.contains(fmKey)) {
                        results.add(indirectChain);
                    }
                }
                continue;
            }

            SensitiveApiHit directChain = matchDirectCall(
                    stmt, info, fileName, functionName, directRules, "CHAIN_EVIDENCE", "FIELD_MAP"
            );
            if (directChain != null) {
                results.add(directChain);
                continue;
            }

            SensitiveApiHit indirectChain = matchIndirectCall(
                    stmt, info, fileName, functionName, indirectRules, "CHAIN_EVIDENCE", "FIELD_MAP", andersen
            );
            if (indirectChain != null) {
                results.add(indirectChain);
            }
        }

        return deduplicate(results);
    }

    private SensitiveApiHit matchDirectCall(
            Stmt stmt,
            ResolvedNameInfo info,
            String fileName,
            String functionName,
            List<PrivacyApiRuleWithPkg> directRules,
            String layer,
            String sourceKind
    ) {
        if (!info.valid || info.lastToken == null) {
            return null;
        }

        String stmtText = safe(stmt);
        boolean assignmentLike = stmtText != null && stmtText.contains("=");

        // Two-pass matching: first try rules with parenthesized arguments (most specific),
        // then fall back to rules without arguments (more general). This ensures that
        // sensor.on('SensorId.ACCELEROMETER') (with specific permission) takes priority
        // over sensor.on (generic) when the argument can be resolved.
        SensitiveApiHit fallbackHit = null;

        for (PrivacyApiRuleWithPkg item : directRules) {
            // Strip parenthesized arguments from the rule method name.
            // Rules like sensor.on('SensorId.ACCELEROMETER') have method="on('SensorId.ACCELEROMETER')",
            // but in the binary IR the API name is just "sensor.on" — the argument is not part of
            // the resolved name. Stripping the parenthesized portion allows matching the base method.
            String baseMethod = stripMethodArguments(item.rule.method);

            if (!methodMatchesPath(info, baseMethod)
                    || !namespaceMatchesForMethod(info.pathTokens, baseMethod, item.rule.namespace)) {
                continue;
            }

            // If the rule has parenthesized arguments, verify them via CallStmt argument inspection.
            // This distinguishes sensor.on(ACCELEROMETER) from sensor.on(GYROSCOPE), enabling
            // correct permission attribution per sensor type.
            String expectedArg = extractMethodArgument(item.rule.method);
            if (expectedArg != null) {
                if (!callStmtArgsMatchArgumentPattern(stmt, stmtText, expectedArg)) {
                    continue; // Argument doesn't match — skip this specific rule
                }
                // Argument matches — this is the most specific match, return immediately
                SensitiveApiHit hit = createBaseHit(stmt, info, fileName, functionName, item, layer, sourceKind);
                hit.category = assignmentLike ? "direct invoke stmt after assignment" : "direct invoke stmt";
                return hit;
            }

            // No parenthesized argument — this is a generic rule. Save as fallback.
            if (fallbackHit == null) {
                fallbackHit = createBaseHit(stmt, info, fileName, functionName, item, layer, sourceKind);
                fallbackHit.category = assignmentLike ? "direct invoke stmt after assignment" : "direct invoke stmt";
            }
        }

        return fallbackHit;
    }

    private SensitiveApiHit matchIndirectCall(
            Stmt stmt,
            ResolvedNameInfo info,
            String fileName,
            String functionName,
            List<PrivacyApiRuleWithPkg> indirectRules,
            String layer,
            String sourceKind,
            Andersen andersen
    ) {
        if (!info.valid || info.pathTokens == null || info.pathTokens.isEmpty()) {
            return null;
        }

        String joinedPath = String.join(".", info.pathTokens);
        String stmtText = safe(stmt);

        // Two-pass matching: prefer rules with matching parenthesized arguments
        SensitiveApiHit fallbackHit = null;

        // Namespace inference for indirect calls: try multiple strategies to determine
        // the namespace of the base variable in an InstanceCallExpr.
        // Priority: Andersen PTA > static type from Local.getType() > resolved name parsing
        Set<String> namespaceCandidates = inferNamespaceCandidatesFromCallBase(stmt, andersen);

        // Track whether candidates came from PTA/static type (InstanceCallExpr) or
        // rootQualifier extraction (static calls). This determines which blocking
        // strategy to use in the heuristic fallback below.
        boolean hasPtaCandidates = !namespaceCandidates.isEmpty();

        // Fallback: extract namespace candidates from the resolved name's rootQualifier
        // or from the joinedPath when it contains user-defined class markers (&...&).
        // This handles static calls (non-InstanceCallExpr) where the call base cannot be
        // analyzed via PTA or static type.
        //
        // Two sources of rootQualifier:
        // 1. info.rootQualifier: set when the resolved name has a colon separator
        //    (e.g., "&entry.src.main.ets.viewmodel.UserViewModel&.#Foreign: unknown register")
        // 2. joinedPath: when the resolved name embeds the class path directly
        //    (e.g., "&entry.src.main.ets.viewmodel.UserViewModel&.#Foreign.register")
        //    In this case, extract from the &...& pattern in joinedPath.
        //
        // Only extract when:
        // - No candidates from PTA/static type (namespaceCandidates is empty)
        // - The extracted path does NOT contain SDK-like paths ("@ohos", "@kit")
        if (namespaceCandidates.isEmpty()) {
            String rqSource = null;
            if (info.rootQualifier != null && !info.rootQualifier.isEmpty()) {
                rqSource = info.rootQualifier;
            } else if (joinedPath != null && joinedPath.contains("&")) {
                // Extract the &...& pattern from joinedPath
                int start = joinedPath.indexOf('&');
                int end = joinedPath.indexOf('&', start + 1);
                if (end > start) {
                    rqSource = joinedPath.substring(start + 1, end);
                }
            }
            if (rqSource != null && !rqSource.isEmpty()) {
                String rqLower = rqSource.toLowerCase(Locale.ROOT);
                boolean isSdkLibrary = rqLower.contains("@ohos") || rqLower.contains("@kit")
                        || rqLower.contains("ohos.") || rqLower.contains("kit.");
                if (!isSdkLibrary) {
                    namespaceCandidates.addAll(extractNamespaceCandidatesFromRootQualifier(rqSource));
                }
            }
        }

        String inferredNamespace = pickBestNamespace(namespaceCandidates);
        String effectivePath = joinedPath;
        if (inferredNamespace != null && !inferredNamespace.isEmpty()) {
            // If the inferred namespace is not already in pathTokens, prepend it
            // so that namespaceMatchesForMethod can use it.
            boolean nsAlreadyInPath = info.pathTokens.contains(inferredNamespace);
            if (!nsAlreadyInPath) {
                effectivePath = inferredNamespace + "." + joinedPath;
            }
        }

        List<String> effectivePathTokens = new ArrayList<>();
        if (inferredNamespace != null && !info.pathTokens.contains(inferredNamespace)) {
            effectivePathTokens.add(inferredNamespace);
        }
        effectivePathTokens.addAll(info.pathTokens);

        for (PrivacyApiRuleWithPkg item : indirectRules) {
            String baseMethod = stripMethodArguments(item.rule.method);

            // Use effectivePathTokens (with inferred namespace) for matching
            boolean pathMatch = (baseMethod != null && !baseMethod.isEmpty()
                    && endsWithDotted(effectivePath, baseMethod)
                    && namespaceMatchesForMethod(effectivePathTokens, baseMethod, item.rule.namespace));

            // Heuristic fallback: if path-based namespace matching fails but the method name
            // uniquely matches an indirect call rule, accept it anyway. This handles cases
            // where the resolved API name lacks proper namespace information.
            //
            // CRITICAL: When ALL inferred namespace candidates CONTRADICT the rule's namespace
            // (e.g., inferred="UserViewModel" vs rule="NetConnection"), the heuristic must be
            // suppressed to prevent false positives like UserViewModel.register being matched
            // as NetConnection.register.
            //
            // Blocking strategies (mutually exclusive):
            // - InstanceCallExpr (hasPtaCandidates): use ONLY ptaClassHasMethod.
            //   PTA already gives precise type info; adding isNamespaceContradicted on top
            //   would double-block and drop legitimate chains.
            // - Static calls (!hasPtaCandidates, rootQualifier-derived): use ONLY
            //   isNamespaceContradicted. These have no PTA, so rootQualifier extraction
            //   is the only source of namespace info for FP blocking.
            if (!pathMatch && baseMethod != null && !baseMethod.isEmpty()) {
                boolean methodOnlyMatch = Objects.equals(baseMethod, info.lastToken)
                        || endsWithDotted(joinedPath, baseMethod);
                if (methodOnlyMatch && isMethodUniqueToNamespace(baseMethod, indirectRules)) {
                    boolean shouldBlock = false;
                    if (hasPtaCandidates) {
                        // InstanceCallExpr: PTA/static type provides candidates.
                        // Only use ptaClassHasMethod — it's precise and sufficient.
                        if (andersen != null) {
                            shouldBlock = ptaClassHasMethod(stmt, andersen, baseMethod);
                        }
                    } else if (!namespaceCandidates.isEmpty()) {
                        // Static call: rootQualifier provides candidates.
                        // Use namespace contradiction as the blocking mechanism.
                        shouldBlock = isNamespaceContradicted(namespaceCandidates, item.rule.namespace);
                    }
                    // else: no candidates at all, allow heuristic (preserve recall)
                    if (!shouldBlock) {
                        pathMatch = true;
                    }
                }
            }

            if (!pathMatch) {
                continue;
            }

            String expectedArg = extractMethodArgument(item.rule.method);
            if (expectedArg != null) {
                if (!callStmtArgsMatchArgumentPattern(stmt, stmtText, expectedArg)) {
                    continue;
                }
                SensitiveApiHit hit = createBaseHit(stmt, info, fileName, functionName, item, layer, sourceKind);
                hit.category = "indirect invoke";
                return hit;
            }

            if (fallbackHit == null) {
                fallbackHit = createBaseHit(stmt, info, fileName, functionName, item, layer, sourceKind);
                fallbackHit.category = "indirect invoke";
            }
        }

        return fallbackHit;
    }

    /**
     * Infers the namespace from the base variable of an InstanceCallExpr using
     * multiple strategies with increasing precision:
     *
     * 1. Andersen PTA points-to analysis: getPointsToHiClasses(base) returns the
     *    set of HiClass objects that the base variable may point to. For each class,
     *    we extract the namespace from getName() or getPackageName(). This is the
     *    most precise method because it uses interprocedural type analysis.
     *
     * 2. Static type from Local.getType(): Fallback to the declared type of the
     *    base variable (first segment of the type string). Less precise but always
     *    available when the variable has a type annotation.
     *
     * @param stmt     The statement potentially containing a call expression
     * @param andersen  The Andersen PTA instance (may be null if call graph failed)
     * @return The set of namespace candidates inferred from the call base, or empty set if inference fails
     */
    private Set<String> inferNamespaceCandidatesFromCallBase(Stmt stmt, Andersen andersen) {
        Set<String> candidates = new LinkedHashSet<>();
        if (!(stmt instanceof CallStmt)) {
            return candidates;
        }
        try {
            CallStmt callStmt = (CallStmt) stmt;
            var callExpr = callStmt.getCallExpr();
            if (callExpr instanceof com.huawei.hianalyzer.ir.value.expr.InstanceCallExpr) {
                com.huawei.hianalyzer.ir.value.expr.InstanceCallExpr instanceCall =
                        (com.huawei.hianalyzer.ir.value.expr.InstanceCallExpr) callExpr;
                var base = instanceCall.getBase();
                if (base != null) {
                    // Strategy 1: Andersen PTA points-to analysis
                    if (andersen != null) {
                        try {
                            Set<com.huawei.hianalyzer.analysis.base.HiClass> ptClasses =
                                    andersen.getPointsToHiClasses(base);
                            if (ptClasses != null && !ptClasses.isEmpty()) {
                                for (var cls : ptClasses) {
                                    candidates.addAll(extractNamespaceCandidatesFromClass(cls));
                                }
                            }
                        } catch (Throwable ignored) {
                            // PTA query failed, fall through to static type
                        }
                    }

                    // Strategy 2: Static type from Local.getType()
                    var type = base.getType();
                    if (type != null) {
                        String typeStr = type.toString();
                        if (typeStr != null && !typeStr.isEmpty()) {
                            int dot = typeStr.indexOf('.');
                            String ns = dot > 0 ? typeStr.substring(0, dot) : typeStr;
                            if (!ns.isEmpty() && !ns.equals("unknown") && !ns.equals("Object")) {
                                candidates.add(ns);
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return candidates;
    }

    /**
     * Extracts namespace candidates from a HiClass object.
     * Returns both the class name and the last segment of the package name,
     * since rules use either as the namespace (e.g., "HttpRequest" or "deviceinfo").
     */
    private Set<String> extractNamespaceCandidatesFromClass(com.huawei.hianalyzer.analysis.base.HiClass cls) {
        Set<String> candidates = new LinkedHashSet<>();
        if (cls == null) return candidates;
        try {
            // Class name (e.g., "HttpRequest", "SystemPasteboard")
            String name = cls.getName();
            if (name != null && !name.isEmpty()) {
                // For nested class names like "pasteboard.SystemPasteboard",
                // extract the last segment
                int dot = name.lastIndexOf('.');
                String lastName = dot >= 0 ? name.substring(dot + 1) : name;
                if (!lastName.isEmpty() && !lastName.equals("Object") && !lastName.equals("unknown")) {
                    candidates.add(lastName);
                }
                // Also add the full name in case the rule uses it
                if (!name.equals(lastName)) {
                    candidates.add(name);
                }
            }
            // Package name last segment (e.g., "http" from "@ohos.net.http")
            String pkg = cls.getPackageName();
            if (pkg != null && !pkg.isEmpty()) {
                int lastDot = pkg.lastIndexOf('.');
                String lastSeg = lastDot >= 0 ? pkg.substring(lastDot + 1) : pkg;
                if (!lastSeg.isEmpty() && !lastSeg.equals("Object") && !lastSeg.equals("unknown")) {
                    candidates.add(lastSeg);
                }
            }
            // For ForeignClass (SDK types), also extract namespace from import path
            // e.g., getFromPath() returns "@ohos.net.http" → add "ohos.net.http" and "http"
            // Note: ForeignClass is NOT a subclass of HiClass, so we check isForeign()
            // on the BaseClass and use the IBaseForeign interface to access SDK info.
            if (cls.isForeign()) {
                try {
                    var ibf = (com.huawei.hianalyzer.common.base.IBaseForeign) cls;
                    String fromPath = ibf.getFromPath();
                    if (fromPath != null && !fromPath.isEmpty()) {
                        String path = fromPath.startsWith("@") ? fromPath.substring(1) : fromPath;
                        if (!path.isEmpty()) {
                            candidates.add(path);
                            int lastDot = path.lastIndexOf('.');
                            if (lastDot > 0) {
                                candidates.add(path.substring(lastDot + 1));
                            }
                        }
                    }
                    String importName = ibf.getImportName();
                    if (importName != null && !importName.isEmpty()) {
                        candidates.add(importName);
                    }
                } catch (Throwable ignored) {}
            }
        } catch (Throwable ignored) {
        }
        return candidates;
    }

    /**
     * Extracts namespace candidates from the rootQualifier of a resolved API name.
     * The rootQualifier is the part before the colon in names like:
     *   "&entry.src.main.ets.viewmodel.UserViewModel&.#Foreign: unknown register"
     *   "com.example.app@ohos: net.http.request"
     *
     * For user-defined classes (containing "entry", "src", "main", "ets", etc.),
     * we extract the class name (last segment before '&') and package segments.
     * These candidates help isNamespaceContradicted detect when a call is to a
     * user-defined class method rather than an SDK API.
     */
    private Set<String> extractNamespaceCandidatesFromRootQualifier(String rootQualifier) {
        Set<String> candidates = new LinkedHashSet<>();
        if (rootQualifier == null || rootQualifier.isEmpty()) {
            return candidates;
        }
        try {
            String rq = rootQualifier.trim();
            // Strip leading '&' and trailing '&' if present
            if (rq.startsWith("&")) rq = rq.substring(1);
            if (rq.endsWith("&")) rq = rq.substring(0, rq.length() - 1);

            // Split by '.' and extract meaningful segments
            String[] segments = rq.split("\\.");
            if (segments.length == 0) return candidates;

            // Add the last segment (likely the class name, e.g., "UserViewModel")
            String lastSeg = segments[segments.length - 1].trim();
            if (!lastSeg.isEmpty() && !lastSeg.equals("unknown") && !lastSeg.equals("Object")) {
                candidates.add(lastSeg);
            }

            // Add the second-to-last segment (likely the package/class context)
            if (segments.length >= 2) {
                String prevSeg = segments[segments.length - 2].trim();
                if (!prevSeg.isEmpty() && !prevSeg.equals("unknown") && !prevSeg.equals("Object")
                        && !prevSeg.equals("src") && !prevSeg.equals("main") && !prevSeg.equals("ets")
                        && !prevSeg.equals("entry")) {
                    candidates.add(prevSeg);
                }
            }

            // Also add the full rootQualifier as a candidate (for prefix matching)
            if (!rq.isEmpty()) {
                candidates.add(rq);
            }
        } catch (Throwable ignored) {
        }
        return candidates;
    }

    /**
     * Checks if any PTA-resolved class for the call's base variable has a method
     * with the given name. If the PTA class itself defines this method, the call
     * is to the class's own implementation, not to an SDK API via dynamic dispatch.
     * This is used to prevent false positives like UserViewModel.register being
     * matched as NetConnection.register.
     */
    private boolean ptaClassHasMethod(Stmt stmt, Andersen andersen, String methodName) {
        if (!(stmt instanceof CallStmt) || andersen == null || methodName == null) {
            return false;
        }
        try {
            CallStmt callStmt = (CallStmt) stmt;
            var callExpr = callStmt.getCallExpr();
            if (callExpr instanceof com.huawei.hianalyzer.ir.value.expr.InstanceCallExpr) {
                var base = ((com.huawei.hianalyzer.ir.value.expr.InstanceCallExpr) callExpr).getBase();
                if (base != null) {
                    Set<com.huawei.hianalyzer.analysis.base.HiClass> ptClasses =
                            andersen.getPointsToHiClasses(base);
                    if (ptClasses != null) {
                        for (var cls : ptClasses) {
                            var funcs = cls.getFunctionByName(methodName);
                            if (funcs != null && !funcs.isEmpty()) {
                                return true;
                            }
                            // Also check if the class name matches the method name
                            // (e.g., class "register" in lambda/anonymous class)
                            String clsName = cls.getName();
                            if (clsName != null && clsName.equalsIgnoreCase(methodName)) {
                                return true;
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    /**
     * When multiple namespace candidates are found via PTA, pick the best one.
     * Prefers namespaces that match known API module patterns (e.g., containing
     * "ohos", "kit", or common SDK identifiers).
     */
    private String pickBestNamespace(Set<String> namespaces) {
        if (namespaces == null || namespaces.isEmpty()) {
            return null;
        }
        // Prefer namespaces that look like SDK modules
        for (String ns : namespaces) {
            String lower = ns.toLowerCase(Locale.ROOT);
            if (lower.contains("ohos") || lower.contains("kit") || lower.contains("system")) {
                return ns;
            }
        }
        // Otherwise return the first one (arbitrary but deterministic due to LinkedHashSet)
        return namespaces.iterator().next();
    }

    /**
     * Checks if a method name uniquely identifies a single namespace among the given rules.
     * This is used as a heuristic fallback: if only one rule has this method name,
     * we can safely match by method name alone even without namespace confirmation.
     *
     * @param method        The method name to check
     * @param indirectRules The list of indirect rules to check against
     * @return true if the method name appears in exactly one rule
     */
    /**
     * Checks whether ALL inferred namespace candidates contradict the rule's namespace.
     * A candidate contradicts if it is non-empty, not equal to the rule namespace,
     * not a prefix/suffix of it, and not an alias of it.
     * If ANY candidate is compatible (including via PACKAGE_ALIASES), we return false
     * (no contradiction). If no candidates exist, we also return false (no evidence
     * of contradiction, so allow the heuristic match).
     */
    private boolean isNamespaceContradicted(Set<String> candidates, String ruleNamespace) {
        if (candidates == null || candidates.isEmpty()) {
            return false; // No evidence → don't block
        }
        // Build a set of all names compatible with the rule namespace (including aliases).
        // Use lowercased versions for comparison since namespace casing can vary
        // (e.g., "Sensor" vs "sensor", "GeoLocationManager" vs "geoLocationManager").
        Set<String> compatibleLower = new HashSet<>();
        compatibleLower.add(ruleNamespace.toLowerCase(Locale.ROOT));
        List<String> aliases = PACKAGE_ALIASES.get(ruleNamespace);
        if (aliases != null) {
            for (String alias : aliases) {
                compatibleLower.add(alias.toLowerCase(Locale.ROOT));
            }
        }
        // Also add derived forms:
        // - @ohos.xxx → ohos.xxx and xxx (last segment)
        // - kit.xxx → xxx (last segment)
        for (String compat : new HashSet<>(compatibleLower)) {
            String withoutAt = compat.startsWith("@") ? compat.substring(1) : compat;
            compatibleLower.add(withoutAt);
            int dot = withoutAt.lastIndexOf('.');
            if (dot > 0) {
                compatibleLower.add(withoutAt.substring(dot + 1));
            }
        }

        // Check if ANY candidate is compatible (case-insensitive)
        for (String candidate : candidates) {
            if (candidate == null || candidate.isEmpty()) continue;
            String candidateLower = candidate.toLowerCase(Locale.ROOT);
            // Direct match
            if (compatibleLower.contains(candidateLower)) return false;
            // Prefix/suffix match (case-insensitive)
            for (String compat : compatibleLower) {
                if (compat.startsWith(candidateLower) || candidateLower.startsWith(compat)) return false;
            }
        }
        // All candidates contradict
        return true;
    }

    private boolean isMethodUniqueToNamespace(String method, List<PrivacyApiRuleWithPkg> indirectRules) {
        if (method == null || indirectRules == null) {
            return false;
        }
        int count = 0;
        for (PrivacyApiRuleWithPkg item : indirectRules) {
            String baseMethod = stripMethodArguments(item.rule.method);
            if (method.equals(baseMethod)) {
                count++;
                if (count > 1) {
                    return false;
                }
            }
        }
        return count == 1;
    }

    private SensitiveApiHit matchPrivacyConstant(
            Stmt stmt,
            ResolvedNameInfo info,
            String fileName,
            String functionName,
            List<PrivacyApiRuleWithPkg> constantRules,
            String layer,
            String sourceKind
    ) {
        if (!info.valid || info.lastToken == null) {
            return null;
        }

        for (PrivacyApiRuleWithPkg item : constantRules) {
            String baseMethod = stripMethodArguments(item.rule.method);

            if (!methodMatchesPath(info, baseMethod)
                    || !namespaceMatchesForMethod(info.pathTokens, baseMethod, item.rule.namespace)) {
                continue;
            }

            SensitiveApiHit hit = createBaseHit(stmt, info, fileName, functionName, item, layer, sourceKind);
            hit.category = "privacy constants";
            return hit;
        }

        return null;
    }

    private SensitiveApiHit createBaseHit(
            Stmt stmt,
            ResolvedNameInfo info,
            String fileName,
            String functionName,
            PrivacyApiRuleWithPkg item,
            String layer,
            String sourceKind
    ) {
        SensitiveApiHit hit = new SensitiveApiHit();
        hit.layer = layer;
        hit.sourceKind = sourceKind;
        hit.systemPackage = item.systemPackage;
        hit.namespace = item.rule.namespace;
        hit.method = item.rule.method;
        hit.permission = item.rule.permission;
        hit.profilingCategory = item.rule.profilingCategory != null
                ? item.rule.profilingCategory
                : item.rule.category;
        hit.dataDirection = item.rule.dataDirection;
        hit.matchedFullName = info.original;
        hit.stmtClass = stmt.getClass().getName();
        hit.stmtText = safe(stmt);
        hit.file = fileName;
        hit.function = functionName;
        hit.stmtIndex = safeStmtIndex(stmt);
        hit.stmtObj = stmt;

        // CFG reachability filter: dead code / unreachable paths get low confidence
        if (!isReachableFromEntry(stmt)) {
            hit.confidence = "low";
            hit.category = "(unreachable) " + hit.category;
        }

        // Def-use filter: if the statement defines a value but nothing uses it,
        // it is likely an unused constant assignment (dead code).
        // This catches cases like: PERMISSION = "xxx" in an unreachable initializer.
        if (!DataFlowExplorer.isValueUsed(stmt)) {
            hit.confidence = "low";
            hit.category = "(unused_def) " + hit.category;
        }

        return hit;
    }

    // ======================================================
    // 7. Call Chain, Method Body, SINK, purposeHint
    // ======================================================

    private UnifiedPrivacyReport.SourceSnippet buildSourceSnippet(HiFunction func, String fileName) {
        UnifiedPrivacyReport.SourceSnippet snippet = new UnifiedPrivacyReport.SourceSnippet();
        snippet.method = safeFunctionName(func);
        snippet.file = fileName;
        snippet.startLine = -1;
        snippet.endLine = -1;
        snippet.code = String.join("\n", safeGetMethodBody(func));
        snippet.originalCode = null;
        return snippet;
    }

    private List<UnifiedPrivacyReport.DataSink> convertDataSinks(
            List<CallStmt> sinkStmts,
            HiFile hiFile,
            String fileName
    ) {
        List<UnifiedPrivacyReport.DataSink> sinks = new ArrayList<>();

        if (sinkStmts == null) {
            return sinks;
        }

        for (CallStmt sinkStmt : sinkStmts) {
            UnifiedPrivacyReport.DataSink sink = new UnifiedPrivacyReport.DataSink();

            String sinkApi = null;
            try {
                sinkApi = hiFile.getFullApiNameByStmt(sinkStmt);
            } catch (Throwable ignored) {
            }

            HiFunction sinkFunc = safeGetHiFunction(sinkStmt);

            sink.sinkApi = sinkApi != null ? sinkApi : safe(sinkStmt);
            sink.sinkMethod = safeFunctionName(sinkFunc);
            sink.sinkFile = fileName;
            sink.sinkLine = safeStmtIndex(sinkStmt);
            sink.sinkType = inferSinkType(sink.sinkApi);

            sinks.add(sink);
        }

        return sinks;
    }

    private UnifiedPrivacyReport.SemanticContext buildSemanticContext(
            List<HiFunction> path,
            Stmt sourceStmt,
            List<UnifiedPrivacyReport.DataSink> dataSinks,
            String fileName
    ) {
        UnifiedPrivacyReport.SemanticContext context = new UnifiedPrivacyReport.SemanticContext();

        HiFunction sourceFunc = safeGetHiFunction(sourceStmt);
        String sourceFuncName = safeFunctionName(sourceFunc);

        context.pageName = inferPageName(fileName);
        context.componentClass = inferComponentClass(sourceFuncName);
        context.semanticAnchor = sourceFuncName;

        List<String> simpleNames = new ArrayList<>();
        if (path != null && !path.isEmpty()) {
            for (HiFunction func : path) {
                simpleNames.add(simplifyFunctionName(safeFunctionName(func)) + "()");
            }
        } else {
            simpleNames.add(simplifyFunctionName(sourceFuncName) + "()");
        }

        String apiText = extractApiTailFromStmt(safe(sourceStmt));
        if (apiText != null && !apiText.isBlank()) {
            simpleNames.add(apiText);
        }

        context.simplifiedChain = String.join(" -> ", simpleNames);

        String sinkText;
        if (dataSinks == null || dataSinks.isEmpty()) {
            sinkText = "no explicit data sink found";
        } else {
            sinkText = dataSinks.stream()
                    .map(s -> s.sinkType + "(" + s.sinkApi + ")")
                    .distinct()
                    .collect(Collectors.joining(", "));
        }

        context.purposeHint = "In "
                + fileName
                + ", function "
                + simplifyFunctionName(sourceFuncName)
                + "() calls "
                + (apiText == null ? "sensitive API" : apiText)
                + ", data flows to "
                + sinkText;

        return context;
    }

    private String inferSinkType(String sinkApi) {
        if (sinkApi == null) {
            return "unknown";
        }

        String s = sinkApi.toLowerCase(Locale.ROOT);

        if (s.contains("console.log") || s.contains("console.info")) {
            return "log";
        }
        if (s.contains("http") || s.contains("request") || s.contains("upload")) {
            return "network";
        }
        if (s.contains("preferences") || s.contains("put") || s.contains("kvstore")) {
            return "storage";
        }

        return "unknown";
    }

    // ======================================================
    // 8. Rule and Name Resolution
    // ======================================================

    private ResolvedNameInfo parseResolvedName(String fullName) {
        ResolvedNameInfo info = new ResolvedNameInfo();
        info.original = fullName;
        info.valid = false;

        if (fullName == null || fullName.isEmpty()) {
            return info;
        }

        String s = fullName.trim();

        if (s.startsWith("@system:")) {
            info.sourcePrefix = "@system";
            s = s.substring(8);
        } else if (s.startsWith("@unknown:")) {
            info.sourcePrefix = "@unknown";
            s = s.substring(9);
        } else if (s.startsWith("@internal:")) {
            info.sourcePrefix = "@internal";
            s = s.substring(10);
        } else if (s.startsWith("@bundle:")) {
            info.sourcePrefix = "@bundle";
            s = s.substring(8);
        } else if (s.startsWith("@import:")) {
            info.sourcePrefix = "@import";
            s = s.substring(8);
        } else {
            info.sourcePrefix = null;
        }

        info.rawBody = s;

        String pathPart = s;
        int colon = s.indexOf(':');
        if (colon >= 0) {
            info.rootQualifier = s.substring(0, colon).trim();
            pathPart = s.substring(colon + 1).trim();
        }

        if (pathPart.isEmpty()) {
            return info;
        }

        for (String p : pathPart.split("\\.")) {
            if (p != null && !p.trim().isEmpty()) {
                info.pathTokens.add(p.trim());
            }
        }

        if (info.pathTokens.isEmpty()) {
            return info;
        }

        info.lastToken = info.pathTokens.get(info.pathTokens.size() - 1);

        if (info.pathTokens.size() > 1) {
            info.prefixTokens = new ArrayList<>(
                    info.pathTokens.subList(0, info.pathTokens.size() - 1)
            );
        }

        info.valid = true;
        return info;
    }

    private boolean isAcceptedResolvedName(ResolvedNameInfo info) {
        if (info == null || !info.valid || info.sourcePrefix == null) {
            return false;
        }

        if ("@unknown".equals(info.sourcePrefix)
                || "@internal".equals(info.sourcePrefix)) {
            return false;
        }

        // @bundle names may resolve to system APIs if the body contains @ohos: namespace.
        // e.g., "@bundle:com.example.app@ohos:net.http.request" → rootQualifier="com.example.app@ohos"
        // The rawBody after stripping @bundle: is "com.example.app@ohos:net.http.request".
        // If the rawBody contains "@ohos:", the resolved name ultimately points to a system API.
        if ("@bundle".equals(info.sourcePrefix)) {
            return info.rawBody != null && info.rawBody.contains("@ohos:");
        }

        return SYSTEM_ONLY_MODE
                ? "@system".equals(info.sourcePrefix)
                : ("@system".equals(info.sourcePrefix) || "@import".equals(info.sourcePrefix));
    }

    private boolean tokenListContains(List<String> tokens, String expected) {
        if (tokens == null || expected == null || expected.isEmpty()) {
            return false;
        }

        for (String token : tokens) {
            if (expected.equals(token)) {
                return true;
            }
        }

        return false;
    }

    private String getSourcePrefix(String fullName) {
        if (fullName == null) {
            return null;
        }
        if (fullName.startsWith("@system:")) {
            return "@system";
        }
        if (fullName.startsWith("@import:")) {
            return "@import";
        }
        if (fullName.startsWith("@internal:")) {
            return "@internal";
        }
        if (fullName.startsWith("@unknown:")) {
            return "@unknown";
        }
        if (fullName.startsWith("@bundle:")) {
            return "@bundle";
        }
        return null;
    }

    /**
     * Detect SSA phi/copy nodes that compilers emit as intermediate IR.
     *
     * Pattern: "vN = vN.<method>" — the left-hand variable equals the right-hand
     * variable (they are the same SSA version). These are NOT real call sites;
     * they represent value-flow merging, not an actual API invocation.
     *
     * Examples we want to skip:
     *   v10 = v10.<write>
     *   v14 = v14.<sdkApiVersion>
     *   v5 = v5.<on>
     *
     * Examples we want to KEEP (different variables):
     *   v10 = v8.<write>
     *   v14 = v3.<sdkApiVersion>
     */
    /**
     * Strict namespace matching: namespace must be the token immediately before method.
     * Prevents false matches like "foo.deviceInfo.bar.productModel" for namespace "deviceInfo".
     */
    private boolean namespaceMustBePredecessor(List<String> pathTokens, String namespace) {
        if (pathTokens == null || namespace == null || namespace.isEmpty()) {
            return false;
        }
        if (pathTokens.size() < 2) {
            return false;
        }
        // pathTokens = [ns, ..., namespace, method] — namespace must be at size-2
        String actualNs = pathTokens.get(pathTokens.size() - 2);
        return namespace.equals(actualNs);
    }

    /**
     * Strips parenthesized arguments from a method name.
     * Handles source-level API patterns like:
     *   "on('SensorId.ACCELEROMETER')" → "on"
     *   "once('SensorId.ACCELEROMETER')" → "once"
     *   "on( 'connectionStateChange')" → "on"
     *
     * In the binary IR, method arguments are not part of the resolved API name,
     * so rules that encode argument patterns in the method field must have those
     * arguments stripped before matching against pathTokens.
     *
     * @param method The rule method field, possibly containing parenthesized arguments
     * @return The base method name without arguments, or the original string if no parentheses
     */
    private String stripMethodArguments(String method) {
        if (method == null || method.isEmpty()) {
            return method;
        }
        int parenIndex = method.indexOf('(');
        if (parenIndex > 0) {
            return method.substring(0, parenIndex).trim();
        }
        return method;
    }

    /**
     * Checks whether a rule's method name matches the path tokens of a resolved API name.
     *
     * Handles both simple method names (e.g., "uploadFile") and compound/dotted
     * method names (e.g., "agent.create") that arise when the source-level API
     * uses a sub-namespace + method pattern.
     *
     * Simple method: exact match against the last token in pathTokens.
     *   method="uploadFile", pathTokens=[net, http, uploadFile] → lastToken="uploadFile" ✓
     *
     * Dotted method: the method tokens must match the suffix of pathTokens.
     *   method="agent.create", pathTokens=[request, agent, create] → suffix [agent, create] ✓
     *
     * @param info       Resolved name info with pathTokens and lastToken
     * @param baseMethod The method name (after stripping parenthesized arguments)
     * @return true if the method matches the path
     */
    private boolean methodMatchesPath(ResolvedNameInfo info, String baseMethod) {
        if (baseMethod == null || baseMethod.isEmpty() || !info.valid) {
            return false;
        }

        // Simple case: no dots — exact match on lastToken
        if (!baseMethod.contains(".")) {
            return Objects.equals(baseMethod, info.lastToken);
        }

        // Dotted method: split into tokens and match suffix of pathTokens.
        // e.g., method="agent.create" → methodTokens=[agent, create]
        //       pathTokens=[request, agent, create] → suffix matches ✓
        String[] methodTokens = baseMethod.split("\\.");
        if (methodTokens.length == 0) {
            return false;
        }

        if (info.pathTokens == null || info.pathTokens.size() < methodTokens.length) {
            return false;
        }

        // Check that the last methodTokens.length tokens of pathTokens match
        int offset = info.pathTokens.size() - methodTokens.length;
        for (int i = 0; i < methodTokens.length; i++) {
            if (!methodTokens[i].equals(info.pathTokens.get(offset + i))) {
                return false;
            }
        }

        return true;
    }

    /**
     * HarmonyOS SDK namespace aliases: maps each namespace to its equivalent
     * alternative names. In HarmonyOS, the same API can be imported via
     * different namespace paths (e.g., @ohos.geoLocationManager vs
     * @kit.LocationKit). When matching rules, we must accept any alias.
     *
     * Ported from the source-level tool's PACKAGE_ALIASES table.
     */
    private static final Map<String, List<String>> PACKAGE_ALIASES = Map.ofEntries(
            Map.entry("@ohos.distributedDeviceManager", List.of("@kit.DistributedServiceKit")),
            Map.entry("@kit.DistributedServiceKit", List.of("@ohos.distributedDeviceManager")),
            Map.entry("@ohos.deviceInfo", List.of("@kit.BasicServicesKit")),
            Map.entry("@kit.BasicServicesKit", List.of("@ohos.deviceInfo", "@ohos.request", "@ohos.pasteboard", "@ohos.account.osAccount", "@ohos.account.appAccount")),
            Map.entry("@ohos.multimedia.audio", List.of("@kit.AudioKit")),
            Map.entry("@kit.AudioKit", List.of("@ohos.multimedia.audio")),
            Map.entry("@ohos.multimedia.camera", List.of("@kit.CameraKit")),
            Map.entry("@kit.CameraKit", List.of("@ohos.multimedia.camera")),
            Map.entry("@ohos.account.osAccount", List.of("@kit.BasicServicesKit")),
            Map.entry("@ohos.account.appAccount", List.of("@kit.BasicServicesKit")),
            Map.entry("@ohos.geoLocationManager", List.of("@kit.LocationKit", "@ohos.geolocation")),
            Map.entry("@ohos.geolocation", List.of("@kit.LocationKit", "@ohos.geoLocationManager")),
            Map.entry("@kit.LocationKit", List.of("@ohos.geoLocationManager", "@ohos.geolocation")),
            Map.entry("@ohos.sensor", List.of("@kit.SensorServiceKit")),
            Map.entry("@kit.SensorServiceKit", List.of("@ohos.sensor")),
            Map.entry("@ohos.wifiManager", List.of("@kit.ConnectivityKit")),
            Map.entry("@kit.ConnectivityKit", List.of("@ohos.wifiManager")),
            // Namespace sub-module aliases: in the binary, APIs like identifier.oaid.getOAID()
            // have pathTokens=["identifier","oaid","getOAID"], but the rule namespace is "identifier".
            // The predecessor token is "oaid", not "identifier", so we need an alias mapping.
            Map.entry("identifier", List.of("oaid"))
    );

    /**
     * Gets all package names that are equivalent to the given package,
     * including the package itself and all its aliases.
     */
    private List<String> getRulePackagesForImport(String pkg) {
        List<String> result = new ArrayList<>();
        result.add(pkg);
        List<String> aliases = PACKAGE_ALIASES.get(pkg);
        if (aliases != null) {
            result.addAll(aliases);
        }
        return result;
    }

    /**
     * Namespace matching that accounts for multi-token (dotted) method names
     * and package aliases.
     *
     * For simple methods: namespace must be the immediate predecessor of the method
     * token in pathTokens (same as {@link #namespaceMustBePredecessor}).
     *
     * For dotted methods like "agent.create" with namespace="request":
     *   pathTokens = [request, agent, create]
     *   The namespace "request" must appear immediately before the first method token "agent",
     *   i.e., at position pathTokens.size() - methodTokenCount - 1.
     *
     * Additionally, if the rule's namespace has aliases (e.g., "@ohos.geoLocationManager"
     * also matches "@kit.LocationKit"), we accept any alias at the namespace position.
     *
     * @param pathTokens  Tokenized path from the resolved API name
     * @param baseMethod  The method name (after stripping parenthesized arguments)
     * @param namespace   The required namespace from the rule
     * @return true if namespace (or any alias) correctly precedes the method in the path
     */
    private boolean namespaceMatchesForMethod(List<String> pathTokens, String baseMethod, String namespace) {
        if (pathTokens == null || namespace == null || namespace.isEmpty() || baseMethod == null) {
            return false;
        }

        int methodTokenCount = baseMethod.contains(".") ? baseMethod.split("\\.").length : 1;
        int namespaceIndex = pathTokens.size() - methodTokenCount - 1;

        if (namespaceIndex < 0) {
            return false;
        }

        String actualNs = pathTokens.get(namespaceIndex);

        // Direct match (case-insensitive to handle "Connection" vs "connection")
        if (namespace.equalsIgnoreCase(actualNs)) {
            return true;
        }

        // Alias match: if the rule's namespace has aliases, check if any alias
        // matches the actual namespace at the expected position (case-insensitive)
        for (String alias : getRulePackagesForImport(namespace)) {
            if (alias.equalsIgnoreCase(actualNs)) {
                return true;
            }
            // Also check if the last segment of the alias matches (e.g., "@kit.LocationKit" → "LocationKit")
            int dot = alias.lastIndexOf('.');
            if (dot > 0 && alias.substring(dot + 1).equalsIgnoreCase(actualNs)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extracts the argument pattern from a parenthesized method name.
     * Handles patterns like:
     *   "on('SensorId.ACCELEROMETER')" → "SensorId.ACCELEROMETER"
     *   "once('SensorId.ACCELEROMETER')" → "SensorId.ACCELEROMETER"
     *   "on('locationChange')" → "locationChange"
     *   "on( 'connectionStateChange')" → "connectionStateChange"
     *
     * The extracted argument is used for argument-based matching: we check
     * whether the CallStmt's actual arguments contain a StringConstant matching
     * this pattern. This enables distinguishing sensor.on(ACCELEROMETER) from
     * sensor.on(GYROSCOPE) for correct permission attribution.
     *
     * @param method The rule method field, possibly containing parenthesized arguments
     * @return The argument pattern (without quotes), or null if no parentheses found
     */
    private String extractMethodArgument(String method) {
        if (method == null || method.isEmpty()) {
            return null;
        }
        int openParen = method.indexOf('(');
        if (openParen < 0) {
            return null;
        }
        int closeParen = method.lastIndexOf(')');
        if (closeParen <= openParen) {
            return null;
        }
        String arg = method.substring(openParen + 1, closeParen).trim();
        // Strip surrounding quotes if present
        if (arg.startsWith("'") && arg.endsWith("'") && arg.length() >= 2) {
            arg = arg.substring(1, arg.length() - 1);
        } else if (arg.startsWith("\"") && arg.endsWith("\"") && arg.length() >= 2) {
            arg = arg.substring(1, arg.length() - 1);
        }
        return arg.isEmpty() ? null : arg;
    }

    /**
     * Checks whether a CallStmt's arguments contain a value matching the expected argument pattern.
     *
     * This is the core of argument-based matching. When a rule specifies a method with
     * parenthesized arguments (e.g., sensor.on('SensorId.ACCELEROMETER')), we need to verify
     * that the actual call site passes an argument consistent with that pattern.
     *
     * Matching strategy:
     * 1. If the expected argument contains a dot (e.g., 'SensorId.ACCELEROMETER'), check if
     *    any StringConstant argument contains the tail segment (e.g., 'ACCELEROMETER').
     *    This handles cases where the enum reference is compiled to a partial string.
     * 2. For simple arguments without dots, check for exact substring match in StringConstant values.
     * 3. Fall back to stmtText pattern matching when call arguments cannot be resolved.
     *
     * @param stmt              The CallStmt to inspect
     * @param stmtText          String representation of the statement (for fallback matching)
     * @param expectedArg       The expected argument pattern from the rule
     * @return true if the statement's arguments match the expected pattern
     */
    private boolean callStmtArgsMatchArgumentPattern(Stmt stmt, String stmtText, String expectedArg) {
        if (expectedArg == null || expectedArg.isEmpty()) {
            return true;
        }

        // Try to extract StringConstant arguments from the CallStmt
        if (stmt instanceof CallStmt) {
            CallStmt callStmt = (CallStmt) stmt;
            try {
                var callExpr = callStmt.getCallExpr();
                if (callExpr != null) {
                    var argList = callExpr.getArgList();
                    if (argList != null) {
                        for (Object arg : argList) {
                            if (arg instanceof com.huawei.hianalyzer.ir.value.constant.StringConstant) {
                                String argValue = ((com.huawei.hianalyzer.ir.value.constant.StringConstant) arg).getValue();
                                if (argValue != null && argumentMatchesPattern(argValue, expectedArg)) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            } catch (Throwable ignored) {
                // Fall through to stmtText matching
            }
        }

        // Fallback: check stmtText for the expected argument pattern.
        // This handles cases where the argument is an SSA variable or enum constant
        // that cannot be resolved to a StringConstant at analysis time.
        // We check for the argument's tail segment (after the last dot) to handle
        // enum-qualified patterns like 'SensorId.ACCELEROMETER'.
        String argTail = expectedArg.contains(".") ? expectedArg.substring(expectedArg.lastIndexOf('.') + 1) : expectedArg;
        return stmtText != null && (
                stmtText.contains(expectedArg) ||  // Full pattern match
                stmtText.contains(argTail)          // Tail-only match (for partial enum refs)
        );
    }

    /**
     * Checks whether an actual argument value matches the expected argument pattern.
     * Supports both exact match and suffix match for enum-qualified patterns.
     *
     * @param actualArg   The actual argument value (e.g., from StringConstant)
     * @param expectedArg The expected pattern from the rule (e.g., "SensorId.ACCELEROMETER")
     * @return true if the actual argument matches the expected pattern
     */
    private boolean argumentMatchesPattern(String actualArg, String expectedArg) {
        if (actualArg == null || expectedArg == null) {
            return false;
        }
        // Exact match
        if (actualArg.equals(expectedArg)) {
            return true;
        }
        // Suffix match: for enum-qualified patterns, check if the tail matches
        // e.g., actual="ACCELEROMETER", expected="SensorId.ACCELEROMETER" → match
        String expectedTail = expectedArg.contains(".") ? expectedArg.substring(expectedArg.lastIndexOf('.') + 1) : expectedArg;
        if (actualArg.equals(expectedTail)) {
            return true;
        }
        // Case-insensitive suffix match for robustness
        if (actualArg.equalsIgnoreCase(expectedTail)) {
            return true;
        }
        // Partial match: expected is substring of actual (for extended enum names)
        if (actualArg.contains(expectedArg)) {
            return true;
        }
        return false;
    }

    /**
     * Checks whether targetStmt is reachable from the function entry point
     * via normal or exceptional control flow edges.
     *
     * Uses Huawei's BlockGraph + DominantTree for efficient block-level reachability,
     * then falls back to StmtGraph BFS for precise statement-level check.
     * Results are cached per function to avoid repeated graph construction.
     *
     * Falls back to "reachable" (fail-open) if CFG construction fails,
     * to avoid false negatives when the analysis tool encounters unusual code.
     */
    private static boolean isReachableFromEntry(Stmt targetStmt) {
        if (targetStmt == null) {
            return false;
        }

        HiFunction func;
        try {
            func = targetStmt.getHiFunction();
        } catch (Throwable t) {
            func = null;
        }
        if (func == null) {
            return true;  // Cannot determine — conservative pass
        }

        try {
            var body = func.getBody();
            if (body == null) {
                return true;
            }

            // Fast path: check if targetStmt is the entry statement
            Stmt entryStmt = body.getEntryStmt();
            if (entryStmt != null && entryStmt == targetStmt) {
                return true;
            }

            // Block-level reachability check using DominantTree
            BlockGraph blockGraph = BlockGraph.createOrGetGraph(func);
            if (blockGraph != null) {
                BasicBlock entryBlock = blockGraph.getEntryBlock();
                if (entryBlock != null) {
                    // Find the block containing targetStmt
                    BasicBlock containingBlock = findContainingBlock(blockGraph, targetStmt);
                    if (containingBlock != null && containingBlock == entryBlock) {
                        return true;  // Stmt is in entry block, reachable
                    }
                    // Use DominantTree for block-level reachability
                    DominantTree domTree = new DominantTree(blockGraph);
                    // BFS on block-level CFG from entry
                    if (isBlockReachableFromEntry(blockGraph, domTree, containingBlock)) {
                        // Stmt is in a reachable block, check within-block position
                        return isStmtReachableInBlock(entryStmt, targetStmt);
                    }
                    return false;  // Block is not reachable
                }
            }

            // Fallback: StmtGraph BFS for precise check
            StmtGraph stmtGraph = Stage.createOrGetStmtGraph(func);
            if (stmtGraph == null) {
                return true;
            }

            Stmt graphEntry = stmtGraph.getEntryStmt();
            if (graphEntry == null || graphEntry == targetStmt) {
                return true;
            }

            return isStmtReachableBFS(stmtGraph, graphEntry, targetStmt);

        } catch (Throwable t) {
            Logger.error("[PreciseScanner] CFG reachability check failed: "
                    + (t.getMessage() != null ? t.getMessage() : t.getClass().getName()));
            return true;  // Fail-open: treat as reachable to avoid missed reports
        }
    }

    /**
     * Finds the BasicBlock containing targetStmt by checking each block's statements.
     */
    private static BasicBlock findContainingBlock(BlockGraph blockGraph, Stmt targetStmt) {
        for (BasicBlock block : blockGraph.getAllBlocks()) {
            for (Stmt s : block.getStmts()) {
                if (s == targetStmt) {
                    return block;
                }
            }
        }
        return null;
    }

    /**
     * Checks if targetBlock is reachable from entry block via block-level CFG.
     * Uses DominantTree for efficient traversal.
     */
    private static boolean isBlockReachableFromEntry(BlockGraph blockGraph, DominantTree domTree, BasicBlock targetBlock) {
        if (targetBlock == null) {
            return true;  // Cannot determine — conservative pass
        }

        BasicBlock entry = blockGraph.getEntryBlock();
        if (entry == null || entry == targetBlock) {
            return true;
        }

        // BFS from entry block
        Set<BasicBlock> visited = new HashSet<>();
        Deque<BasicBlock> queue = new ArrayDeque<>();
        queue.add(entry);
        visited.add(entry);
        

        while (!queue.isEmpty()) {
            BasicBlock current = queue.poll();
            for (BasicBlock succ : blockGraph.getSuccsOf(current)) {
                if (succ == targetBlock) {
                    return true;
                }
                if (!visited.contains(succ)) {
                    visited.add(succ);
                    queue.add(succ);
                }
            }
        }
        return false;
    }

    /**
     * Checks if targetStmt is reachable from entryStmt within the same block.
     * For simplicity, we consider all statements in a reachable block as reachable.
     */
    private static boolean isStmtReachableInBlock(Stmt entryStmt, Stmt targetStmt) {
        // Within the same block, all statements after the entry are reachable
        // This is a simplification; for precise check we'd need dominance frontiers
        return true;  // Conservative: if block is reachable, stmt is reachable
    }

    /**
     * BFS from entry to target within a StmtGraph.
     */
    private static boolean isStmtReachableBFS(StmtGraph graph, Stmt entry, Stmt target) {
        Set<Stmt> visited = new HashSet<>();
        Deque<Stmt> queue = new ArrayDeque<>();
        queue.add(entry);
        visited.add(entry);

        while (!queue.isEmpty()) {
            Stmt current = queue.poll();
            for (Stmt succ : graph.getSuccsOf(current)) {
                if (succ == target) {
                    return true;
                }
                if (!visited.contains(succ)) {
                    visited.add(succ);
                    queue.add(succ);
                }
            }
        }
        return false;
    }

    private List<PrivacyPackageInfo> loadPrivacyApis(String jsonPath) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper.readValue(new File(jsonPath), new TypeReference<List<PrivacyPackageInfo>>() {});
    }

    private List<PrivacyApiRuleWithPkg> flattenRules(List<PrivacyPackageInfo> packageInfos) {
        List<PrivacyApiRuleWithPkg> res = new ArrayList<>();

        if (packageInfos == null) {
            return res;
        }

        for (PrivacyPackageInfo pkg : packageInfos) {
            if (pkg == null || pkg.privacyApis == null) {
                continue;
            }

            for (PrivacyApiRule rule : pkg.privacyApis) {
                if (rule == null) {
                    continue;
                }

                PrivacyApiRuleWithPkg item = new PrivacyApiRuleWithPkg();
                item.systemPackage = pkg.systemPackage;
                item.rule = rule;
                res.add(item);
            }
        }

        return res;
    }

    /**
     * Applies SSA transformation to all functions in the HiFile (when ENABLE_SSA is true).
     * Uses Huawei's SSA.getInstance().transform(Body) for in-place normalization.
     * This converts phi nodes and copies into explicit SSA form,
     * enabling more accurate def-use analysis and reachability checks.
     *
     * Note: TypeInfer is for V2 only, not needed for V1 ArkTS.
     */
    private void transformWithSSA(HiFile hiFile) {
        if (!ENABLE_SSA) {
            return;
        }

        try {
            SSA ssa = SSA.getInstance();

            int transformedFuncs = 0;
            for (HiFunction func : hiFile.getHiFunctions()) {
                try {
                    var body = func.getBody();
                    if (body == null) {
                        continue;
                    }

                    // SSA transformation: inserts phi nodes, renames variables
                    ssa.transform(body);
                    transformedFuncs++;
                } catch (Throwable t) {
                    // Individual function failure should not abort entire file
                    // (null body is expected for interface/declaration-only methods)
                    Logger.log("[PreciseScanner] SSA skipped (no body): "
                            + safeFunctionName(func));
                }
            }

            if (transformedFuncs > 0) {
                Logger.log("    [*] SSA transformed " + transformedFuncs + " functions");
            }
        } catch (Throwable t) {
            Logger.error("[PreciseScanner] SSA transformation failed: " + t.getMessage());
            // Fail-open: continue without SSA transformation
        }
    }

    // ======================================================
    // 9. Inference and Formatting Utilities
    // ======================================================

    private String normalizeApiPackage(String systemPackage) {
        if (systemPackage == null || systemPackage.isBlank()) {
            return "UnknownPackage";
        }
        return systemPackage;
    }

    private String inferArkTsProfilingCategory(String namespace, String method, String systemPackage) {
        String ns = namespace == null ? "" : namespace.toLowerCase(Locale.ROOT);
        String m = method == null ? "" : method.toLowerCase(Locale.ROOT);
        String pkg = systemPackage == null ? "" : systemPackage.toLowerCase(Locale.ROOT);

        if (ns.contains("deviceinfo") || pkg.contains("basicservices")) {
            if (m.contains("serial") || m.contains("udid") || m.contains("oaid")) {
                return "device_identity.unique_id";
            }
            if (m.contains("os") || m.contains("version") || m.contains("sdk") || m.contains("build")) {
                return "device_identity.software";
            }
            return "device_identity.hardware";
        }

        if (ns.contains("battery")) {
            return "device_status.battery";
        }

        if (ns.contains("geolocation") || ns.contains("location")) {
            return "location";
        }

        if (ns.contains("wifi")) {
            return "network.wifi";
        }

        if (ns.contains("bluetooth") || ns.contains("access")) {
            return "network.bluetooth";
        }

        if (ns.contains("connection") || ns.contains("net")) {
            return "network.connectivity";
        }

        if (ns.contains("contact")) {
            return "user_data.contacts";
        }

        if (ns.contains("sms")) {
            return "user_data.sms";
        }

        if (ns.contains("sensor")) {
            return "device_status.sensor";
        }

        if (ns.contains("identifier") || m.contains("oaid")) {
            return "device_identity.ad_tracking";
        }

        if (ns.contains("pasteboard") || ns.contains("clipboard")) {
            return "user_data.clipboard";
        }

        return "unknown";
    }

    private String inferArkTsRisk(String profilingCategory, String permission) {
        String pc = profilingCategory == null ? "" : profilingCategory.toLowerCase(Locale.ROOT);

        if (pc.contains("location")
                || pc.contains("contacts")
                || pc.contains("sms")
                || pc.contains("unique_id")
                || pc.contains("ad_tracking")) {
            return "high";
        }

        if (permission != null && !permission.isBlank()) {
            return "medium";
        }

        return "medium";
    }

    private List<String> extractArgsFromStmt(String stmtText) {
        List<String> args = new ArrayList<>();

        if (stmtText == null) {
            return args;
        }

        int l = stmtText.lastIndexOf('(');
        int r = stmtText.lastIndexOf(')');

        if (l < 0 || r <= l) {
            return args;
        }

        String body = stmtText.substring(l + 1, r).trim();

        if (body.isEmpty()) {
            return args;
        }

        for (String part : body.split(",")) {
            String arg = part.trim();
            if (!arg.isEmpty()) {
                args.add(arg);
            }
        }

        return args;
    }

    private String extractApiTailFromStmt(String stmtText) {
        if (stmtText == null) {
            return null;
        }

        int dot = stmtText.lastIndexOf('.');
        if (dot < 0 || dot + 1 >= stmtText.length()) {
            return null;
        }

        String tail = stmtText.substring(dot + 1)
                .replace(">", "")
                .replace("<", "")
                .replace("()", "")
                .trim();

        int paren = tail.indexOf('(');
        if (paren >= 0) {
            tail = tail.substring(0, paren).trim();
        }

        return tail.isEmpty() ? null : tail;
    }

    private String inferEntryMethodType(HiFunction func) {
        String name = safeFunctionName(func);
        String lowerName = name.toLowerCase(Locale.ROOT);

        // HarmonyOS ArkUI Component Lifecycle Methods
        if (lowerName.contains(".build") || lowerName.contains("aboutToAppear") ||
            lowerName.contains("aboutToDisappear") || lowerName.contains("onpageshow") ||
            lowerName.contains("onpagehide") || lowerName.contains("onbackpress") ||
            lowerName.contains("onready") || lowerName.contains("ondisposed") ||
            lowerName.contains("oninit") || lowerName.contains("onstart") ||
            lowerName.contains("onstop") || lowerName.contains("onactive") ||
            lowerName.contains("oninactive") || lowerName.contains("onforeground") ||
            lowerName.contains("onbackground")) {
            return "component_lifecycle";
        }

        // HarmonyOS Ability Lifecycle Methods
        if (lowerName.contains("onabilitycreate") || lowerName.contains("onabilitydestroy") ||
            lowerName.contains("onabilityforeground") || lowerName.contains("onabilitybackground") ||
            lowerName.contains("onwindowstagecreate") || lowerName.contains("onwindowstagedestroy") ||
            lowerName.contains("oncontinue") || lowerName.contains("onnewwant") ||
            lowerName.contains("ondump") || lowerName.contains("onrequest")) {
            return "ability_lifecycle";
        }

        // HarmonyOS ArkUI Component Constructors
        // Pattern: XXXComponent, XXXPage, XXXView, Builder classes
        if (name.endsWith("Component") || name.endsWith("Page") ||
            name.endsWith("View") || name.endsWith("Builder") ||
            name.endsWith("Element") || name.endsWith("Item") ||
            // Common component patterns
            lowerName.contains("listcomponent") || lowerName.contains("gridcomponent") ||
            lowerName.contains("buttoncomponent") || lowerName.contains("textcomponent") ||
            lowerName.contains("imagecomponent") || lowerName.contains("webcomponent") ||
            lowerName.contains("inputcomponent") || lowerName.contains("switchcomponent") ||
            lowerName.contains("slidercomponent") || lowerName.contains("checkboxcomponent") ||
            lowerName.contains("radiocomponent") || lowerName.contains("togglecomponent") ||
            lowerName.contains("dialogcomponent") || lowerName.contains("popupcomponent") ||
            lowerName.contains("tabcomponent") || lowerName.contains("navcomponent") ||
            // Uni-app / cross-platform component
            lowerName.contains("page") && !lowerName.contains("onpage")) {
            return "ui_component";
        }

        // Event Handlers (UI events)
        if (lowerName.contains("onclick") || lowerName.contains("onchange") ||
            lowerName.contains("oninput") || lowerName.contains("onsubmit") ||
            lowerName.contains("ontouchstart") || lowerName.contains("ontouchmove") ||
            lowerName.contains("ontouchend") || lowerName.contains("onscroll") ||
            lowerName.contains("onswipe") || lowerName.contains("onlongpress") ||
            lowerName.contains("%am") || lowerName.contains("%o_click") ||
            lowerName.contains("handler_click") || lowerName.contains("handler_change")) {
            return "event_handler";
        }

        // Async Callbacks (Promise, async callbacks)
        if (lowerName.contains("callback") || lowerName.contains("then(") ||
            lowerName.contains("catch(") || lowerName.contains("%resolve") ||
            lowerName.contains("%reject") || lowerName.contains("_callback_") ||
            lowerName.contains("_success") || lowerName.contains("_fail") ||
            lowerName.contains("_complete")) {
            return "async_callback";
        }

        // Entry Points
        if (name.equals("func_main_0") || name.startsWith("func_")) {
            return "entry_point";
        }

        return "method";
    }

    private String inferCallType(HiFunction caller, HiFunction callee) {
        String callerName = safeFunctionName(caller).toLowerCase(Locale.ROOT);
        String calleeName = safeFunctionName(callee).toLowerCase(Locale.ROOT);

        // Component lifecycle -> event handler
        if (callerName.contains(".build") || callerName.contains("aboutToAppear")) {
            if (calleeName.contains("onclick") || calleeName.contains("%am") ||
                calleeName.contains("handler") || calleeName.contains("callback")) {
                return "lifecycle_trigger";
            }
        }

        // Event handler patterns
        if (callerName.contains("onclick") || callerName.contains("%o_click") ||
            callerName.contains("ontouch") || callerName.contains("onsubmit")) {
            return "event_handler_call";
        }

        // Async callbacks
        if (callerName.contains("callback") || callerName.contains("%resolve") ||
            callerName.contains("%reject") || callerName.contains("then(")) {
            return "async_callback_call";
        }

        // Ability lifecycle
        if (callerName.contains("onInit") || callerName.contains("onCreate") ||
            callerName.contains("onReady")) {
            return "lifecycle_init";
        }

        return "direct";
    }

    private String inferPageName(String fileName) {
        if (fileName == null) {
            return "unknown";
        }

        String s = fileName.replace("\\", "/");
        int slash = s.lastIndexOf('/');
        if (slash >= 0) {
            s = s.substring(slash + 1);
        }

        if (s.endsWith(".abc")) {
            return s.substring(0, s.length() - 4);
        }

        int dot = s.lastIndexOf('.');
        if (dot > 0) {
            return s.substring(0, dot);
        }

        return s;
    }

    private String inferComponentClass(String functionName) {
        if (functionName == null || functionName.isBlank()) {
            return "UnknownClass";
        }

        String s = simplifyFunctionName(functionName);
        int dot = s.indexOf('.');
        if (dot > 0) {
            return s.substring(0, dot);
        }

        return "UnknownClass";
    }

    private String simplifyFunctionName(String name) {
        if (name == null) {
            return "Unknown";
        }

        String s = name;

        // Handle HarmonyOS internal function IDs like #65045#
        // These are compiler-generated functions, try to extract meaningful name
        if (s.matches("#\\d+#")) {
            return "[anonymous_func:" + s + "]";
        }

        // Handle lambda patterns like $func$123 or lambda$123
        if (s.matches(".*lambda\\$\\d+.*") || s.matches("\\$func\\$\\d+.*")) {
            return "[lambda:" + s.substring(0, Math.min(20, s.length())) + "]";
        }

        // Handle closure patterns
        if (s.contains("$closure$") || s.contains("%closure%")) {
            return "[closure]";
        }

        int colon = s.lastIndexOf(':');
        if (colon >= 0 && colon + 1 < s.length()) {
            s = s.substring(colon + 1).trim();
        }

        s = s.replace("[static]", "").trim();

        int paren = s.indexOf('(');
        if (paren >= 0) {
            s = s.substring(0, paren).trim();
        }

        // Remove module path prefixes like @bundle:&@xxx&
        if (s.contains("&")) {
            int amp = s.lastIndexOf('&');
            if (amp > 0 && amp + 1 < s.length()) {
                s = s.substring(amp + 1).trim();
            }
        }

        return s;
    }

    // ======================================================
    // 10. Safe Access Utilities
    // ======================================================

    private Map<Stmt, String> safeGetAllStmtApiNameMap(HiFile hiFile) {
        try {
            Map<Stmt, String> map = hiFile.getAllStmtApiNameMap();
            return map == null ? Collections.emptyMap() : map;
        } catch (Throwable t) {
            return Collections.emptyMap();
        }
    }

    private Map<Stmt, String> safeGetAllStmtFieldNameMap(HiFile hiFile) {
        try {
            Map<Stmt, String> map = hiFile.getAllStmtFieldNameMap();
            return map == null ? Collections.emptyMap() : map;
        } catch (Throwable t) {
            return Collections.emptyMap();
        }
    }

    private List<String> safeGetMethodBody(HiFunction func) {
        List<String> bodyStmts = new ArrayList<>();

        if (func == null) {
            return bodyStmts;
        }

        try {
            if (func.getBody() == null || func.getBody().getStmts() == null) {
                return bodyStmts;
            }

            for (Stmt stmt : func.getBody().getStmts()) {
                bodyStmts.add(String.valueOf(stmt));
            }

        } catch (Throwable t) {
            bodyStmts.add("<Failed to extract internal statements>");
        }

        return bodyStmts;
    }

    private HiFunction safeGetHiFunction(Stmt stmt) {
        try {
            return stmt == null ? null : stmt.getHiFunction();
        } catch (Throwable t) {
            return null;
        }
    }

    private String safeFunctionName(HiFunction func) {
        if (func == null) {
            return "<null>";
        }

        try {
            String name = func.getName();
            return name == null ? "<unnamed>" : name;
        } catch (Throwable t) {
            return safe(func);
        }
    }

    private int safeStmtIndex(Stmt stmt) {
        try {
            return stmt == null ? -1 : stmt.getIndex();
        } catch (Throwable t) {
            return -1;
        }
    }

    private boolean isSsaPhiNode(String stmtText) {
        if (stmtText == null || stmtText.isEmpty()) {
            return false;
        }

        // Must look like an assignment: vN = vN.<method>
        int eq = stmtText.indexOf('=');
        if (eq <= 0 || eq + 1 >= stmtText.length()) {
            return false;
        }

        String lhs = stmtText.substring(0, eq).trim();
        String rhs = stmtText.substring(eq + 1).trim();

        // LHS must be a single SSA variable (v + digits)
        if (!lhs.matches("v\\d+")) {
            return false;
        }

        // RHS must be a VirtualCall with the SAME variable
        if (!rhs.startsWith("VirtualCall: ")) {
            // Could be "vN = vN.<method>" without "VirtualCall:" prefix
            if (rhs.startsWith(lhs + ".")) {
                return true;
            }
            return false;
        }

        // Inside VirtualCall: the receiver must be the same variable
        // e.g., "VirtualCall: v10.<write>" -> receiver is "v10"
        String inside = rhs.substring("VirtualCall: ".length()).trim();
        if (inside.startsWith(lhs + ".")) {
            return true;
        }

        return false;
    }

    private String safe(Object obj) {
        if (obj == null) {
            return null;
        }

        try {
            return String.valueOf(obj);
        } catch (Throwable t) {
            return null;
        }
    }

    private String safePath(File file) {
        if (file == null) {
            return "<null>";
        }

        try {
            return file.getAbsolutePath();
        } catch (Throwable t) {
            return String.valueOf(file);
        }
    }

    private String normalizeFullName(String s) {
        return s == null ? null : s.trim();
    }

    private boolean endsWithDotted(String full, String suffix) {
        return full != null
                && suffix != null
                && (full.equals(suffix) || full.endsWith("." + suffix));
    }

    private List<SensitiveApiHit> deduplicate(List<SensitiveApiHit> hits) {
        Map<String, SensitiveApiHit> map = new LinkedHashMap<>();

        for (SensitiveApiHit hit : hits) {
            // Include stmtText in dedup key to avoid duplicates from stmtApiMap + stmtFieldMap
            String key = hit.file
                    + "|" + hit.function
                    + "|" + hit.stmtIndex
                    + "|" + hit.layer
                    + "|" + hit.category
                    + "|" + hit.sourceKind
                    + "|" + hit.systemPackage
                    + "|" + hit.namespace
                    + "|" + hit.method
                    + "|" + hit.matchedFullName
                    + "|" + (hit.stmtText != null ? hit.stmtText : "");

            map.putIfAbsent(key, hit);
        }

        return new ArrayList<>(map.values());
    }

    private String buildHitDedupKey(SensitiveApiHit hit) {
        return hit.file
                + "|" + hit.function
                + "|" + hit.stmtIndex
                + "|" + hit.layer
                + "|" + hit.category
                + "|" + hit.sourceKind
                + "|" + hit.systemPackage
                + "|" + hit.namespace
                + "|" + hit.method
                + "|" + hit.matchedFullName
                + "|" + (hit.stmtText != null ? hit.stmtText : "");
    }

    private void collectAbcFiles(File file, List<File> result) throws IOException {
        if (file == null || !file.exists()) {
            return;
        }

        if (file.isFile()) {
            if (file.getName().toLowerCase(Locale.ROOT).endsWith(".abc")) {
                result.add(file);
            }
            return;
        }

        Files.walk(file.toPath())
                .filter(Files::isRegularFile)
                .filter(p -> p.toString().toLowerCase(Locale.ROOT).endsWith(".abc"))
                .forEach(p -> result.add(p.toFile()));
    }

    // ======================================================
    // 11. Standalone Debug Entry Point
    // ======================================================

    public static void main(String[] args) throws Exception {
        String targetDirectory = args.length >= 1
                ? args[0]
                : "sample/C6917602215994202990_1.0.0";

        String ruleJsonPath = args.length >= 2
                ? args[1]
                : "config/privacy_apis.json";

        String outputPath = args.length >= 3
                ? args[2]
                : "out/arkts_scan_debug.json";

        PreciseSensitiveApiScanner scanner = new PreciseSensitiveApiScanner();
        ArkTsScanResult scanResult = scanner.scanDirectory(targetDirectory, ruleJsonPath);

        UnifiedPrivacyReport report = new UnifiedPrivacyReport();
        report.projectName = new File(targetDirectory).getName();
        report.projectDirectory = new File(targetDirectory).getAbsolutePath();
        report.analysisTimestamp = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ")
                .format(new Date());

        report.privacyApiUsages.addAll(scanResult.arktsApiUsages);
        report.callChains.addAll(scanResult.callChains);

        report.summary.arktsApiUsages = scanResult.arktsApiUsages.size();
        report.summary.totalApiUsages = scanResult.arktsApiUsages.size();
        report.summary.callChainCount = scanResult.callChains.size();
        report.summary.analyzedAbcCount = scanResult.analyzedAbcCount;
        report.summary.warnings.addAll(scanResult.warnings);

        int dataSinkCount = 0;
        for (UnifiedPrivacyReport.CallChainReport chain : report.callChains) {
            if (chain.dataSinks != null) {
                dataSinkCount += chain.dataSinks.size();
            }
        }
        report.summary.dataSinkCount = dataSinkCount;

        File outFile = new File(outputPath);
        File parent = outFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        mapper.writeValue(outFile, report);

        Logger.log("[+] ArkTS debug report saved to: " + outFile.getAbsolutePath());
    }
}