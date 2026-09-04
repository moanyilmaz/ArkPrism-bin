package com.huawei.hisec;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.huawei.hianalyzer.analysis.Stage;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.base.HiFunction;
import com.huawei.hianalyzer.analysis.graph.callgraph.CallGraph;
import com.huawei.hianalyzer.analysis.graph.callgraph.pta.andersen.Andersen;
import com.huawei.hianalyzer.frontend.metainterface.SourceLang;
import com.huawei.hianalyzer.ir.bodytransformer.ssa.SSA;
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
     * Enable CAIR (Conflict-Aware and Alias-Consistent API Identity Recovery) algorithm.
     * When true, indirect calls are resolved in batch using alias component analysis,
     * multi-evidence scoring, and entropy-based ambiguity assessment instead of the
     * per-call-site heuristic cascade. When false, falls back to the original logic.
     */
    private static final boolean USE_CAIR = Boolean.parseBoolean(
            System.getProperty("arkprism.cair.enabled", "true"));
    /**
     * Enable SSA transformation before scanning.
     * SSA converts phi nodes and copies into explicit SSA form, enabling more accurate
     * def-use analysis. It can be expensive for large codebases.
     * Default: false (disabled for better performance)
     */
    private static final boolean ENABLE_SSA = false;

    /**
     * Generic verb method names that are too common to match by method name alone.
     * When a method-only heuristic match lands on one of these names and there is
     * no namespace evidence (no PTA candidates, no rootQualifier, no variable name),
     * the heuristic is blocked to prevent false positives like:
     *   - UserViewModel.register → NetConnection.register
     *   - MyServer.stop → WebSocketServer.stop
     */
    private static final Set<String> GENERIC_METHOD_BLACKLIST = Set.of(
            "register", "unregister",
            "start", "stop", "restart",
            "on", "off",
            "open", "close",
            "connect", "disconnect",
            "send", "receive",
            "get", "set",
            "add", "remove",
            "enable", "disable",
            "init", "destroy",
            "load", "save",
            "create", "delete",
            "read", "write",
            "lock", "unlock",
            "bind", "unbind",
            "subscribe", "unsubscribe",
            "show", "hide",
            "play", "pause", "resume"
    );

    /**
     * Cache of indirect rules for the current scan, used by isAcceptedResolvedName
     * to check if @bundle calls match a known privacy API method name.
     */
    private List<PrivacyApiRuleWithPkg> indirectRulesCache = Collections.emptyList();

    // ======================================================
    // 1. JSON Rule Models
    // ======================================================

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
        public String apiSignature;
        public String dataType;
        public String label;
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

        List<PrivacyApiRuleWithPkg> allRules;
        try {
            allRules = loadPrivacyApis(ruleJsonFile.getAbsolutePath());
        } catch (IOException e) {
            result.warnings.add("Failed to load privacy rule json: " + e.getMessage());
            return result;
        }

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

            try {
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

                // Add deduplicated usages to the result immediately (incremental save).
                // This ensures partial results are preserved even if a later ABC crashes.
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
            } catch (Throwable t) {
                // Per-ABC error isolation: a crash in one ABC (e.g., OOM during
                // call chain construction) must not discard results already collected
                // from this or previous ABCs. Log the error and continue.
                String msg = "ABC analysis crashed: " + abcFile.getAbsolutePath() + " - " + safeMessage(t);
                result.warnings.add(msg);
                Logger.error("[-] " + msg);
            }
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
        return ScannerUtils.inferEntryMethodTypeByName(functionName);
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
        usage.apiSignature = hit.apiSignature;
        usage.dataType = hit.dataType;
        usage.label = hit.label;
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

        // Cache indirect rules for isAcceptedResolvedName
        this.indirectRulesCache = indirectRules;

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

        // ── CAIR batch collection ──
        // When USE_CAIR=true, collect all indirect call sites into a batch,
        // resolve them with CaiResolver at the end, then merge results.
        List<Object[]> cairCallSiteData = USE_CAIR ? new ArrayList<>() : null;
        Map<Stmt, String[]> cairStmtMeta = USE_CAIR ? new LinkedHashMap<>() : null;
        // meta: [layer, sourceKind, isSsaPattern]

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

            // Indirect call: use CAIR or original path
            if (USE_CAIR) {
                // Collect for batch processing
                cairCallSiteData.add(new Object[]{stmt, fullApiName, fileName, functionName});
                cairStmtMeta.put(stmt, new String[]{"BODY_HIT", "API_MAP", "false"});
            } else {
                SensitiveApiHit indirectHit = matchIndirectCall(
                        stmt, info, fileName, functionName, indirectRules, "BODY_HIT", "API_MAP", andersen, hiFile, cg
                );
                if (indirectHit != null) {
                    results.add(indirectHit);
                    stmtsWithApiMapHit.add(stmt);
                    apiMapFunctionMethodKeys.add(functionName + "|" + indirectHit.namespace + "|" + indirectHit.method);
                }
            }
        }

        for (Map.Entry<Stmt, String> entry : stmtFieldMap.entrySet()) {
            Stmt stmt = entry.getKey();
            String fullFieldName = normalizeFullName(entry.getValue());

            if (stmt == null || fullFieldName == null || fullFieldName.isEmpty()) {
                continue;
            }

            if (stmtsWithApiMapHit.contains(stmt)) {
                continue;
            }

            String stmtText = safe(stmt);
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

            if (isSsaPattern) {
                if (USE_CAIR) {
                    // Collect for batch processing
                    cairCallSiteData.add(new Object[]{stmt, fullFieldName, fileName, functionName});
                    cairStmtMeta.put(stmt, new String[]{"CHAIN_EVIDENCE", "FIELD_MAP", "true"});
                } else {
                    SensitiveApiHit indirectChain = matchIndirectCall(
                            stmt, info, fileName, functionName, indirectRules, "CHAIN_EVIDENCE", "FIELD_MAP", andersen, hiFile, cg
                    );
                    if (indirectChain != null) {
                        String fmKey = functionName + "|" + indirectChain.namespace + "|" + indirectChain.method;
                        if (!apiMapFunctionMethodKeys.contains(fmKey)) {
                            results.add(indirectChain);
                        }
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

            // Indirect call: use CAIR or original path
            if (USE_CAIR) {
                cairCallSiteData.add(new Object[]{stmt, fullFieldName, fileName, functionName});
                cairStmtMeta.put(stmt, new String[]{"CHAIN_EVIDENCE", "FIELD_MAP", "false"});
            } else {
                SensitiveApiHit indirectChain = matchIndirectCall(
                        stmt, info, fileName, functionName, indirectRules, "CHAIN_EVIDENCE", "FIELD_MAP", andersen, hiFile, cg
                );
                if (indirectChain != null) {
                    results.add(indirectChain);
                }
            }
        }

        // ── CAIR batch resolution ──
        if (USE_CAIR && cairCallSiteData != null && !cairCallSiteData.isEmpty()) {
            Map<Stmt, CaiResolver.ResolutionResult> cairResults = CaiResolver.resolve(
                    cairCallSiteData, indirectRules, andersen, cg, hiFile);

            for (Map.Entry<Stmt, CaiResolver.ResolutionResult> entry : cairResults.entrySet()) {
                Stmt stmt = entry.getKey();
                CaiResolver.ResolutionResult rr = entry.getValue();
                if (rr.bestCandidate == null) continue;

                // Skip ambiguous results — they match but with low confidence
                if (rr.isAmbiguous) {
                    Logger.log("  [CAIR] Ambiguous (entropy=" + String.format("%.2f", rr.entropy)
                            + "): " + rr.callSite.methodName + " → " + rr.bestCandidate.namespace);
                    continue;
                }

                String[] meta = cairStmtMeta.get(stmt);
                String layer = meta != null ? meta[0] : "BODY_HIT";
                String sourceKind = meta != null ? meta[1] : "API_MAP";
                boolean isSsa = meta != null && "true".equals(meta[2]);

                SensitiveApiHit hit = CaiResolver.toSensitiveApiHit(rr, layer, sourceKind);
                if (hit == null) continue;

                // For SSA patterns, apply the same cross-map dedup as the original path
                if (isSsa) {
                    String fmKey = hit.function + "|" + hit.namespace + "|" + hit.method;
                    if (apiMapFunctionMethodKeys.contains(fmKey)) {
                        continue;
                    }
                }

                results.add(hit);
                stmtsWithApiMapHit.add(stmt);
                apiMapFunctionMethodKeys.add(hit.function + "|" + hit.namespace + "|" + hit.method);

                if (rr.certificate != null) {
                    Logger.log("  [CAIR] " + rr.certificate.decisionRationale);
                }
            }
        }

        // Clear reachability cache after scanning this HiFile to prevent memory leaks
        ReachabilityAnalyzer.clearCache();

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

        SensitiveApiHit bestHit = null;
        int bestScore = Integer.MIN_VALUE;

        for (PrivacyApiRuleWithPkg item : directRules) {
            // Strip parenthesized arguments from the rule method name.
            // Rules like sensor.on('SensorId.ACCELEROMETER') have method="on('SensorId.ACCELEROMETER')",
            // but in the binary IR the API name is just "sensor.on" — the argument is not part of
            // the resolved name. Stripping the parenthesized portion allows matching the base method.
            String baseMethod = stripMethodArguments(item.rule.method);

            if (!methodMatchesPath(info, baseMethod)
                    || !reviewedNamespaceMatches(info.pathTokens, baseMethod, item.rule)) {
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
            }

            int score = reviewedRuleEvidenceScore(stmt, info, item);
            if (expectedArg != null) {
                score += 100;
            }
            if (score > bestScore) {
                bestHit = createBaseHit(
                        stmt, info, fileName, functionName, item, layer, sourceKind);
                bestHit.category = assignmentLike
                        ? "direct invoke stmt after assignment" : "direct invoke stmt";
                bestScore = score;
            }
        }

        return bestHit;
    }

    private SensitiveApiHit matchIndirectCall(
            Stmt stmt,
            ResolvedNameInfo info,
            String fileName,
            String functionName,
            List<PrivacyApiRuleWithPkg> indirectRules,
            String layer,
            String sourceKind,
            Andersen andersen,
            HiFile hiFile,
            CallGraph cg
    ) {
        if (!info.valid || info.pathTokens == null || info.pathTokens.isEmpty()) {
            return null;
        }

        String joinedPath = String.join(".", info.pathTokens);
        String stmtText = safe(stmt);

        SensitiveApiHit bestHit = null;
        int bestScore = Integer.MIN_VALUE;

        // Namespace inference for indirect calls: try multiple strategies to determine
        // the namespace of the base variable in an InstanceCallExpr.
        // Priority: Andersen PTA > static type from Local.getType() > resolved name parsing
        Set<String> namespaceCandidates = inferNamespaceCandidatesFromCallBase(stmt, andersen, cg);

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

        // Validate the inferred namespace against HiFile and known SDK namespaces.
        // If it doesn't correspond to any known class and isn't a recognized SDK namespace,
        // clear it to prevent false positive matching.
        if (inferredNamespace != null && hiFile != null) {
            if (!NamespaceResolver.namespaceExistsInHiFile(inferredNamespace, hiFile)
                    && !NamespaceResolver.isKnownSdkNamespace(inferredNamespace)) {
                inferredNamespace = null;
            }
        }

        // Use the ORIGINAL joinedPath for path matching, not a modified version.
        // Previously, the inferred namespace was prepended to effectivePath, which
        // could break endsWithDotted matching when the inferred namespace was wrong
        // (e.g., injecting "AccountInfo" before "account.distributedAccount...").
        // The inferred namespace is only used for the heuristic fallback below.
        String effectivePath = joinedPath;
        List<String> effectivePathTokens = new ArrayList<>(info.pathTokens);

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
            // The heuristic is ONLY allowed when there is SOME namespace evidence (either from
            // PTA/static type, rootQualifier, or variable name). Without any namespace evidence,
            // matching by method name alone is too aggressive and causes FP.
            //
            // Blocking strategies (mutually exclusive):
            // - InstanceCallExpr with PTA candidates: use ONLY ptaClassHasMethod.
            // - Any candidates present: use isNamespaceContradicted.
            // - No candidates at all: block the heuristic (don't allow method-only match).
            if (!pathMatch && baseMethod != null && !baseMethod.isEmpty()) {
                // Strip arguments from lastToken for comparison, since the rule method name
                // doesn't include argument types but the resolved name might (e.g., "getSupportedCameras(unknown)")
                String lastTokenStripped = stripMethodArguments(info.lastToken);
                boolean methodOnlyMatch = Objects.equals(baseMethod, lastTokenStripped)
                        || endsWithDotted(joinedPath, baseMethod);
                if (methodOnlyMatch && isMethodUniqueToNamespace(baseMethod, indirectRules)) {
                    // Method is unique to a single namespace (accounting for aliases).
                    // Block the heuristic if:
                    // 1. The method is a generic verb (register, stop, etc.) and there's no
                    //    namespace evidence — these are too common to match without context.
                    // 2. We have POSITIVE namespace evidence that contradicts the rule's namespace.
                    boolean shouldBlock = false;
                    if (GENERIC_METHOD_BLACKLIST.contains(baseMethod.toLowerCase(Locale.ROOT))
                            && !hasPtaCandidates && namespaceCandidates.isEmpty()) {
                        shouldBlock = true;
                    } else if (hasPtaCandidates || !namespaceCandidates.isEmpty()) {
                        shouldBlock = isNamespaceContradicted(namespaceCandidates, item.rule.namespace);
                    }
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
            }

            int score = reviewedRuleEvidenceScore(stmt, info, item);
            if (expectedArg != null) {
                score += 100;
            }
            if (score > bestScore) {
                bestHit = createBaseHit(
                        stmt, info, fileName, functionName, item, layer, sourceKind);
                bestHit.category = "indirect invoke";
                bestScore = score;
            }
        }

        return bestHit;
    }

    private Set<String> inferNamespaceCandidatesFromCallBase(Stmt stmt, Andersen andersen, CallGraph cg) {
        return NamespaceResolver.inferNamespaceCandidatesFromCallBase(stmt, andersen, cg);
    }

    private Set<String> extractNamespaceCandidatesFromClass(com.huawei.hianalyzer.common.base.BaseClass<?, ?> cls) {
        return NamespaceResolver.extractNamespaceCandidatesFromClass(cls);
    }

    private Set<String> extractNamespaceCandidatesFromRootQualifier(String rootQualifier) {
        return NamespaceResolver.extractNamespaceCandidatesFromRootQualifier(rootQualifier);
    }

    private Set<String> inferNamespaceFromAssignment(Local base, Stmt usageStmt, Andersen andersen, CallGraph cg) {
        return NamespaceResolver.inferNamespaceFromAssignment(base, usageStmt, andersen, cg);
    }

    private List<Stmt> findDefinitionStmts(Local base, Stmt usageStmt, Andersen andersen, CallGraph cg) {
        return NamespaceResolver.findDefinitionStmts(base, usageStmt, andersen, cg);
    }

    private Set<String> extractNamespaceCandidatesFromReturnType(com.huawei.hianalyzer.common.type.Type returnType) {
        return NamespaceResolver.extractNamespaceCandidatesFromReturnType(returnType);
    }

    private boolean ptaClassHasMethod(Stmt stmt, Andersen andersen, String methodName) {
        return NamespaceResolver.ptaClassHasMethod(stmt, andersen, methodName);
    }

    private String pickBestNamespace(Set<String> namespaces) {
        return NamespaceResolver.pickBestNamespace(namespaces);
    }

    private boolean isNamespaceContradicted(Set<String> candidates, String ruleNamespace) {
        return NamespaceResolver.isNamespaceContradicted(candidates, ruleNamespace);
    }

    private boolean isMethodUniqueToNamespace(String method, List<PrivacyApiRuleWithPkg> indirectRules) {
        return NamespaceResolver.isMethodUniqueToNamespace(method, indirectRules);
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
        hit.apiSignature = item.rule.apiSignature;
        hit.dataType = item.rule.dataType;
        hit.label = item.rule.label;
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
        return ScannerUtils.buildSourceSnippet(func, fileName);
    }

    private List<UnifiedPrivacyReport.DataSink> convertDataSinks(
            List<CallStmt> sinkStmts,
            HiFile hiFile,
            String fileName
    ) {
        return ScannerUtils.convertDataSinks(sinkStmts, hiFile, fileName);
    }

    private UnifiedPrivacyReport.SemanticContext buildSemanticContext(
            List<HiFunction> path,
            Stmt sourceStmt,
            List<UnifiedPrivacyReport.DataSink> dataSinks,
            String fileName
    ) {
        return ScannerUtils.buildSemanticContext(path, sourceStmt, dataSinks, fileName);
    }

    private String inferSinkType(String sinkApi) {
        return ScannerUtils.inferSinkType(sinkApi);
    }

    // ======================================================
    // 8. Rule and Name Resolution
    // ======================================================

    private ResolvedNameInfo parseResolvedName(String fullName) {
        return NamePathMatcher.parseResolvedName(fullName);
    }

    private boolean isAcceptedResolvedName(ResolvedNameInfo info) {
        if (info == null || !info.valid || info.sourcePrefix == null) {
            return false;
        }

        // @unknown and @internal are always rejected regardless of SYSTEM_ONLY_MODE
        if ("@unknown".equals(info.sourcePrefix)
                || "@internal".equals(info.sourcePrefix)) {
            return false;
        }

        // @bundle names may resolve to system APIs if the body contains @ohos: namespace.
        // Also accept @bundle names where the last pathToken matches a known privacy API
        // method name — these are calls resolved from the application's own code that
        // invoke privacy-sensitive APIs (e.g., getSupportedCameras resolved from
        // @bundle:com.legado...camera.#GLOBAL.getSupportedCameras).
        if ("@bundle".equals(info.sourcePrefix)) {
            if (info.rawBody != null && info.rawBody.contains("@ohos:")) {
                return true;
            }
            // Check if the last pathToken matches a known indirect API method name
            if (info.lastToken != null) {
                String lastStripped = stripMethodArguments(info.lastToken).toLowerCase(Locale.ROOT);
                for (PrivacyApiRuleWithPkg rule : indirectRulesCache) {
                    String ruleMethod = stripMethodArguments(rule.rule.method).toLowerCase(Locale.ROOT);
                    if (lastStripped.equals(ruleMethod)) {
                        return true;
                    }
                }
            }
            return false;
        }

        // Delegate to NamePathMatcher for the standard acceptance logic, but respect
        // this class's SYSTEM_ONLY_MODE flag which NamePathMatcher doesn't have.
        return SYSTEM_ONLY_MODE
                ? "@system".equals(info.sourcePrefix)
                : ("@system".equals(info.sourcePrefix) || "@import".equals(info.sourcePrefix));
    }

    private boolean tokenListContains(List<String> tokens, String expected) {
        return NamePathMatcher.tokenListContains(tokens, expected);
    }

    private String getSourcePrefix(String fullName) {
        return NamePathMatcher.getSourcePrefix(fullName);
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
    private boolean namespaceMustBePredecessor(List<String> pathTokens, String namespace) {
        return NamePathMatcher.namespaceMustBePredecessor(pathTokens, namespace);
    }

    private String stripMethodArguments(String method) {
        return NamePathMatcher.stripMethodArguments(method);
    }

    private boolean methodMatchesPath(ResolvedNameInfo info, String baseMethod) {
        return NamePathMatcher.methodMatchesPath(info, baseMethod);
    }

    private List<String> getRulePackagesForImport(String pkg) {
        return NamespaceResolver.getRulePackagesForImport(pkg);
    }

    private boolean namespaceMatchesForMethod(List<String> pathTokens, String baseMethod, String namespace) {
        return NamePathMatcher.namespaceMatchesForMethod(pathTokens, baseMethod, namespace);
    }

    private String extractMethodArgument(String method) {
        return NamePathMatcher.extractMethodArgument(method);
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
        // The tail segment (after last dot) is used for enum-qualified patterns
        // like 'SensorId.ACCELEROMETER'. A minimum length of 3 chars avoids
        // matching short fragments like "on" or "get" that appear in many statements.
        String argTail = expectedArg.contains(".") ? expectedArg.substring(expectedArg.lastIndexOf('.') + 1) : expectedArg;
        if (stmtText == null) return false;
        if (stmtText.contains(expectedArg)) return true;
        if (argTail.length() >= 3 && stmtText.contains(argTail)) return true;
        return false;
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
     * Ranks otherwise matching reviewed rules using evidence that survives in
     * bytecode. Missing description or module evidence never blocks a match.
     */
    private int reviewedRuleEvidenceScore(
            Stmt stmt, ResolvedNameInfo info, PrivacyApiRuleWithPkg item) {
        if (item == null || item.rule == null) {
            return 0;
        }
        int score = 0;

        Integer actualArgumentCount = getCallArgumentCount(stmt);
        Integer minimum = item.rule.minimumArgumentCount;
        Integer maximum = item.rule.maximumArgumentCount;
        if (actualArgumentCount != null && minimum != null && maximum != null) {
            if (actualArgumentCount >= minimum && actualArgumentCount <= maximum) {
                score += 8;
            } else {
                score -= 2;
            }
        }

        score += reviewedModuleEvidenceScore(
                info, item.rule.sdkModule, item.systemPackage);
        if (item.rule.moduleAlias != null && info != null && info.pathTokens != null) {
            for (String token : info.pathTokens) {
                if (item.rule.moduleAlias.equalsIgnoreCase(token)) {
                    score += 4;
                    break;
                }
            }
        }
        return score;
    }

    private boolean reviewedNamespaceMatches(
            List<String> pathTokens, String baseMethod, PrivacyApiRule rule) {
        if (rule == null) {
            return false;
        }
        if (namespaceMatchesForMethod(pathTokens, baseMethod, rule.namespace)) {
            return true;
        }
        if (rule.namespace == null || !rule.namespace.isEmpty()
                || rule.moduleAlias == null || pathTokens == null) {
            return false;
        }
        int methodTokenCount = baseMethod != null && baseMethod.contains(".")
                ? baseMethod.split("\\.").length : 1;
        int aliasIndex = pathTokens.size() - methodTokenCount - 1;
        return aliasIndex >= 0
                && rule.moduleAlias.equalsIgnoreCase(pathTokens.get(aliasIndex));
    }

    private Integer getCallArgumentCount(Stmt stmt) {
        if (!(stmt instanceof CallStmt)) {
            return null;
        }
        try {
            var callExpr = ((CallStmt) stmt).getCallExpr();
            if (callExpr == null || callExpr.getArgList() == null) {
                return null;
            }
            return callExpr.getArgList().size();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private int reviewedModuleEvidenceScore(
            ResolvedNameInfo info, String sdkModule, String systemPackage) {
        if (info == null || info.original == null) {
            return 0;
        }
        String resolved = normalizeModuleEvidence(info.original);
        int score = 0;

        if (sdkModule != null && !sdkModule.isBlank()) {
            String module = normalizeModuleEvidence(sdkModule);
            if (resolved.contains(module)) {
                score += 12;
            } else if ((module.startsWith("@ohos.") && resolved.contains("@hms."))
                    || (module.startsWith("@hms.") && resolved.contains("@ohos."))) {
                score -= 4;
            }
        }

        if (systemPackage != null && !systemPackage.isBlank()
                && resolved.contains(normalizeModuleEvidence(systemPackage))) {
            score += 6;
        }
        return score;
    }

    private String normalizeModuleEvidence(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT)
                .replace(':', '.');
    }

    private boolean isReachableFromEntry(Stmt targetStmt) {
        return ReachabilityAnalyzer.isReachableFromEntry(targetStmt);
    }


    private List<PrivacyApiRuleWithPkg> loadPrivacyApis(String jsonPath) throws IOException {
        List<PrivacyApiRuleWithPkg> res = new ArrayList<>();
        for (PrivacyApiConfigLoader.LoadedRule loaded
                : PrivacyApiConfigLoader.load(new File(jsonPath))) {
            PrivacyApiRuleWithPkg item = new PrivacyApiRuleWithPkg();
            item.systemPackage = loaded.systemPackage;
            item.rule = loaded.rule;
            res.add(item);
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
        return ScannerUtils.normalizeApiPackage(systemPackage);
    }

    private String inferArkTsProfilingCategory(String namespace, String method, String systemPackage) {
        return ScannerUtils.inferArkTsProfilingCategory(namespace, method, systemPackage);
    }

    private String inferArkTsRisk(String profilingCategory, String permission) {
        return ScannerUtils.inferArkTsRisk(profilingCategory, permission);
    }

    private List<String> extractArgsFromStmt(String stmtText) {
        return ScannerUtils.extractArgsFromStmt(stmtText);
    }

    private String extractApiTailFromStmt(String stmtText) {
        return ScannerUtils.extractApiTailFromStmt(stmtText);
    }

    private String inferEntryMethodType(HiFunction func) {
        return ScannerUtils.inferEntryMethodType(func);
    }

    private String inferCallType(HiFunction caller, HiFunction callee) {
        return ScannerUtils.inferCallType(caller, callee);
    }

    private String inferPageName(String fileName) {
        return ScannerUtils.inferPageName(fileName);
    }

    private String inferComponentClass(String functionName) {
        return ScannerUtils.inferComponentClass(functionName);
    }

    private String simplifyFunctionName(String name) {
        return ScannerUtils.simplifyFunctionName(name);
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
        return ScannerUtils.safeGetMethodBody(func);
    }

    private HiFunction safeGetHiFunction(Stmt stmt) {
        return ScannerUtils.safeGetHiFunction(stmt);
    }

    private String safeFunctionName(HiFunction func) {
        return ScannerUtils.safeFunctionName(func);
    }

    private int safeStmtIndex(Stmt stmt) {
        return ScannerUtils.safeStmtIndex(stmt);
    }

    private boolean isSsaPhiNode(String stmtText) {
        return ScannerUtils.isSsaPhiNode(stmtText);
    }

    private String safe(Object obj) {
        return ScannerUtils.safe(obj);
    }

    private String safePath(File file) {
        return ScannerUtils.safePath(file);
    }

    private static String safeMessage(Throwable t) {
        if (t == null) return "unknown error";
        String msg = t.getMessage();
        return (msg == null || msg.isBlank()) ? t.getClass().getSimpleName() : msg;
    }

    private String normalizeFullName(String s) {
        return ScannerUtils.normalizeFullName(s);
    }

    private boolean endsWithDotted(String full, String suffix) {
        return ScannerUtils.endsWithDotted(full, suffix);
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
