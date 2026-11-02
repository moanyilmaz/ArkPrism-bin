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
     * CAIR (probabilistic inference) is DISABLED.
     * The scanner now uses HiAnalyzer's deterministic output exclusively:
     * - getAllStmtApiNameMap(): deterministic Stmt → full API name
     * - getAllStmtFieldNameMap(): deterministic Stmt → full field name
     * - Foreign functions/fields/classes: import alias → API name mapping
     * All rules (direct + indirect + constant) are matched via deterministic
     * path-token suffix matching against HiAnalyzer's resolved names.
     */
    private static final boolean USE_CAIR = false;
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
            "play", "pause", "resume",
            // Common method names that appear on many @bundle/@internal classes
            // and cause FPs when method-name-only fallback matches them to privacy APIs
            "getdata", "getthumbnail", "getthumbnailsync",
            "checksysintegrity",
            "requestimage", "requestimagedata",
            "getalbums"
    );

    /**
     * Cache of indirect rules for the current scan, used by isAcceptedResolvedName
     * to check if @bundle calls match a known privacy API method name.
     */
    private List<PrivacyApiRuleWithPkg> indirectRulesCache = Collections.emptyList();
    private List<PrivacyApiRuleWithPkg> directRulesCache = Collections.emptyList();
    private List<PrivacyApiRuleWithPkg> constantRulesCache = Collections.emptyList();

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

                    // Create dedup key from usage fields.
                    // Key: code + declaringMethod + apiSignature + stmtIndex
                    // - code + declaringMethod identifies the source-level call site
                    // - apiSignature ensures duplicate rules (callback + Promise variants
                    //   of the same API in privacy_apis.json) merge into one hit
                    // - stmtIndex distinguishes distinct IR statements that may share
                    //   the same code text (e.g., same statement in if/else branches)
                    String usageKey = (usage.code != null ? usage.code : "")
                            + "|" + (usage.declaringMethod != null ? usage.declaringMethod : "")
                            + "|" + (usage.apiSignature != null ? usage.apiSignature : "")
                            + "|" + hit.stmtIndex;

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

        // Cache rules for isAcceptedResolvedName
        this.indirectRulesCache = indirectRules;
        this.directRulesCache = directRules;
        this.constantRulesCache = constantRules;

        // ── Build deterministic import-alias map from HiAnalyzer Foreign* APIs ──
        // ForeignFunction.getImportName() / getAsName() / getFromPath() provide
        // deterministic mapping from source-level import aliases to full API module paths.
        // ForeignField provides the same for field-level imports.
        // This is used to resolve indirect calls where the source uses a variable
        // obtained from a factory method (e.g., createAppAccountManager → AppAccountManager).
        Map<String, String> importAliasMap = buildImportAliasMap(hiFile);

        // Build a set of all @ohos.* / @kit.* modules actually imported in this abc file.
        // Used as a necessary-condition gate for method-only fallback matching:
        // if the rule's SDK module is not imported, the API call is impossible.
        Set<String> importedSdkModules = buildImportedSdkModules(hiFile);

        // Merge all rules into a single list for unified deterministic matching
        List<PrivacyApiRuleWithPkg> allMatchRules = new ArrayList<>(directRules);
        allMatchRules.addAll(indirectRules);

        Map<Stmt, String> stmtApiMap = safeGetAllStmtApiNameMap(hiFile);
        Map<Stmt, String> stmtFieldMap = safeGetAllStmtFieldNameMap(hiFile);

        // Track Stmts that already produced an API_MAP hit to prevent cross-map duplication
        Set<Stmt> stmtsWithApiMapHit = new HashSet<>();
        Set<String> apiMapFunctionMethodKeys = new HashSet<>();

        // ── Phase 1: Match API call statements via getAllStmtApiNameMap() ──
        // HiAnalyzer deterministically resolves each Stmt to a full API name like
        // @system:@ohos:wifiManager.getLinkedInfo or
        // @system:@ohos:account.appAccount.createAppAccountManager.getAllAccounts
        for (Map.Entry<Stmt, String> entry : stmtApiMap.entrySet()) {
            Stmt stmt = entry.getKey();
            String fullApiName = normalizeFullName(entry.getValue());

            if (stmt == null || fullApiName == null || fullApiName.isEmpty()) {
                continue;
            }

            ResolvedNameInfo info = parseResolvedName(fullApiName);
            if (!isAcceptedResolvedName(info)) {
                continue;
            }

            HiFunction func = safeGetHiFunction(stmt);
            String functionName = safeFunctionName(func);

            // Try direct match first (directCall=true rules)
            List<SensitiveApiHit> directHits = matchDirectCallAll(
                    stmt, info, fileName, functionName, directRules, "BODY_HIT", "API_MAP"
            );
            if (!directHits.isEmpty()) {
                results.addAll(directHits);
                stmtsWithApiMapHit.add(stmt);
                for (SensitiveApiHit h : directHits) {
                    apiMapFunctionMethodKeys.add(functionName + "|" + h.namespace + "|" + h.method);
                }
                continue;
            }

            // Try constant/property match (directCall=null rules, e.g. deviceInfo.serial)
            SensitiveApiHit constHit = matchPrivacyConstant(
                    stmt, info, fileName, functionName, constantRules, "BODY_HIT", "API_MAP"
            );
            if (constHit != null) {
                results.add(constHit);
                stmtsWithApiMapHit.add(stmt);
                apiMapFunctionMethodKeys.add(functionName + "|" + constHit.namespace + "|" + constHit.method);
                continue;
            }

            // Deterministic indirect match: use path-token suffix matching with alias resolution
            // HiAnalyzer gives us the full path like account.appAccount.createAppAccountManager.getAllAccounts
            // We match this against indirect rules using suffix matching + alias mapping
            SensitiveApiHit indirectHit = matchDeterministicIndirect(
                    stmt, info, fileName, functionName, indirectRules, "BODY_HIT", "API_MAP", importAliasMap, importedSdkModules, cg
            );
            if (indirectHit != null) {
                results.add(indirectHit);
                stmtsWithApiMapHit.add(stmt);
                apiMapFunctionMethodKeys.add(functionName + "|" + indirectHit.namespace + "|" + indirectHit.method);
            }
        }

        // ── Phase 2: Match field access statements via getAllStmtFieldNameMap() ──
        // Handles property accesses like deviceInfo.serial, deviceInfo.ODID
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

            // Try constant/property matching first (directCall=null rules)
            SensitiveApiHit fieldHit = matchPrivacyConstant(
                    stmt, info, fileName, functionName, constantRules, "BODY_HIT", "FIELD_MAP"
            );
            if (fieldHit != null) {
                results.add(fieldHit);
                continue;
            }

            // Skip property-write assignments for direct and indirect call rules.
            // Pattern: "vN.<methodName> = value" — this writes a property to an object,
            // it is NOT an API call. Real API calls via FIELD_MAP are field reads like
            // "vN = deviceInfo.serial" (reading from an SDK object).
            // This prevents FPs where app code assigns properties named after privacy
            // APIs (e.g., obj.getSystemInfoSync = null in UniApp framework).
            boolean isPropertyWrite = stmtText != null
                    && stmtText.matches("v\\d+\\.<[^>]+>\\s*=.*");

            if (isPropertyWrite) {
                continue;
            }

            if (isSsaPattern) {
                // SSA phi pattern: try deterministic indirect match with cross-map dedup
                SensitiveApiHit indirectChain = matchDeterministicIndirect(
                        stmt, info, fileName, functionName, indirectRules, "CHAIN_EVIDENCE", "FIELD_MAP", importAliasMap, importedSdkModules, cg
                );
                if (indirectChain != null) {
                    String fmKey = functionName + "|" + indirectChain.namespace + "|" + indirectChain.method;
                    if (!apiMapFunctionMethodKeys.contains(fmKey)) {
                        results.add(indirectChain);
                    }
                }
                continue;
            }

            // Try direct match
            SensitiveApiHit directChain = matchDirectCall(
                    stmt, info, fileName, functionName, directRules, "CHAIN_EVIDENCE", "FIELD_MAP"
            );
            if (directChain != null) {
                results.add(directChain);
                continue;
            }

            // Deterministic indirect match
            SensitiveApiHit indirectChain = matchDeterministicIndirect(
                    stmt, info, fileName, functionName, indirectRules, "CHAIN_EVIDENCE", "FIELD_MAP", importAliasMap, importedSdkModules, cg
            );
            if (indirectChain != null) {
                results.add(indirectChain);
            }
        }

        // Clear reachability cache after scanning this HiFile to prevent memory leaks
        ReachabilityAnalyzer.clearCache();

        return deduplicate(results);
    }

    /**
     * Builds a deterministic import-alias map from HiAnalyzer's Foreign* APIs.
     *
     * ForeignFunction.getImportName() gives the source-level module name (e.g., "appAccount")
     * ForeignFunction.getAsName() gives the local alias (e.g., "appAccountMgr")
     * ForeignFunction.getFromPath() gives the import path (e.g., "@ohos.account.appAccount")
     *
     * This creates mappings like:
     *   createAppAccountManager → AppAccountManager  (factory method → class name)
     *   getCalendarManager → CalendarManager
     *   getUserAuthInstance → UserAuthInstance
     *   getSystemPasteboard → SystemPasteboard
     *   getDistributedAccountAbility → DistributedAccountAbility
     *   getAccountManager → AccountManager (osAccount)
     *
     * Also maps from ForeignClass/ForeignField import names to their full module paths.
     */
    private Map<String, String> buildImportAliasMap(HiFile hiFile) {
        Map<String, String> aliasMap = new HashMap<>();

        // From ForeignFunctions: extract factory method → return type class name
        try {
            for (var ff : hiFile.getForeignFunctions()) {
                String importName = ff.getImportName();
                String asName = ff.getAsName();
                String fromPath = ff.getFromPath();
                String funcName = ff.getName();

                if (funcName == null) continue;

                // Factory method pattern: getXxxManager → XxxManager
                String factoryClass = extractFactoryReturnClass(funcName);
                if (factoryClass != null) {
                    aliasMap.put(funcName, factoryClass);
                }
            }
        } catch (Throwable t) {
            // Non-fatal: alias map just won't have factory mappings
        }

        // From ForeignClasses: map class import names to their full @ohos paths
        try {
            for (var fc : hiFile.getForeignClasses()) {
                String importName = fc.getImportName();
                String asName = fc.getAsName();
                String fromPath = fc.getFromPath();

                if (importName != null && fromPath != null) {
                    // e.g., importName="AppAccountManager", fromPath="@ohos.account.appAccount"
                    aliasMap.put(importName, fromPath);
                    if (asName != null && !asName.equals(importName)) {
                        aliasMap.put(asName, fromPath);
                    }
                }
            }
        } catch (Throwable t) {
            // Non-fatal
        }

        // From ForeignFields: map field import names to their full paths
        try {
            for (var ffield : hiFile.getForeignFields()) {
                String importName = ffield.getImportName();
                String asName = ffield.getAsName();
                String fromPath = ffield.getFromPath();

                if (importName != null && fromPath != null) {
                    aliasMap.putIfAbsent(importName, fromPath);
                    if (asName != null && !asName.equals(importName)) {
                        aliasMap.putIfAbsent(asName, fromPath);
                    }
                }
            }
        } catch (Throwable t) {
            // Non-fatal
        }

        return aliasMap;
    }

    /**
     * Builds a set of all SDK module paths (@ohos.* / @kit.*) actually imported
     * in this HiFile, collected from ForeignClasses, ForeignFunctions, and ForeignFields.
     *
     * Each entry is normalized to lowercase for case-insensitive comparison.
     * Non-SDK imports (e.g., @dcloudio.*, @normalized:*) are excluded.
     */
    private Set<String> buildImportedSdkModules(HiFile hiFile) {
        Set<String> imported = new HashSet<>();
        try {
            for (var fc : hiFile.getForeignClasses()) {
                String fromPath = normalizeImportPath(fc.getFromPath());
                if (fromPath != null) imported.add(fromPath);
            }
        } catch (Throwable ignored) {}
        try {
            for (var ff : hiFile.getForeignFunctions()) {
                String fromPath = normalizeImportPath(ff.getFromPath());
                if (fromPath != null) imported.add(fromPath);
            }
        } catch (Throwable ignored) {}
        try {
            for (var ffield : hiFile.getForeignFields()) {
                String fromPath = normalizeImportPath(ffield.getFromPath());
                if (fromPath != null) imported.add(fromPath);
            }
        } catch (Throwable ignored) {}
        return imported;
    }

    /**
     * Normalizes an import path from HiAnalyzer's ForeignClasses/Functions/Fields
     * to a canonical lowercase form suitable for matching against rule apiPackages.
     *
     * HiAnalyzer returns paths like "@system:@ohos:file.photoaccesshelper" — the
     * "@system:" prefix is HiAnalyzer's internal classification, not part of the
     * actual import path. We strip it and normalize to get "@ohos:file.photoaccesshelper".
     *
     * @param fromPath raw fromPath from HiAnalyzer
     * @return normalized lowercase path, or null if not an SDK import
     */
    private String normalizeImportPath(String fromPath) {
        if (fromPath == null) return null;
        String s = fromPath;
        // Strip @system: prefix (HiAnalyzer internal classification)
        if (s.startsWith("@system:")) {
            s = s.substring(8);
        }
        if (s.contains("@ohos:") || s.contains("@kit:")
                || s.startsWith("@ohos.") || s.startsWith("@kit.")) {
            return s.toLowerCase(Locale.ROOT);
        }
        return null;
    }

    /**
     * Checks whether a rule's SDK module (apiPackage / systemPackage) is present
     * in the set of actually imported modules, considering PACKAGE_ALIASES.
     *
     * Returns true if:
     * - The rule has no apiPackage (can't gate, allow)
     * - The rule's apiPackage is found in importedSdkModules (directly or via alias)
     * - The rule's namespace maps to an imported module via PACKAGE_ALIASES
     *
     * Returns false only when we have positive evidence that the module is NOT imported.
     */
    private boolean isRuleModuleImported(PrivacyApiRuleWithPkg item, Set<String> importedSdkModules) {
        if (importedSdkModules == null || importedSdkModules.isEmpty()) {
            return true; // Can't gate, allow
        }

        String apiPkg = item.systemPackage != null ? item.systemPackage : item.rule.apiPackage;
        if (apiPkg == null || apiPkg.isEmpty()) {
            return true; // Can't gate, allow
        }

        String pkgLower = apiPkg.toLowerCase(Locale.ROOT);

        // Direct match
        if (importedSdkModules.contains(pkgLower)) {
            return true;
        }

        // Alias match: check if any alias of apiPkg is imported
        List<String> aliases = NamespaceResolver.getRulePackagesForImport(apiPkg);
        if (aliases != null) {
            for (String alias : aliases) {
                if (alias != null && importedSdkModules.contains(alias.toLowerCase(Locale.ROOT))) {
                    return true;
                }
            }
        }

        // Also check namespace-based aliases (e.g., namespace "Calendar" → @ohos.calendarManager)
        if (item.rule.namespace != null && !item.rule.namespace.isEmpty()) {
            List<String> nsAliases = NamespaceResolver.getRulePackagesForImport(item.rule.namespace);
            if (nsAliases != null) {
                for (String alias : nsAliases) {
                    if (alias != null && importedSdkModules.contains(alias.toLowerCase(Locale.ROOT))) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Extracts the class name from a factory method name.
     * e.g., "createAppAccountManager" → "AppAccountManager"
     *       "getCalendarManager" → "CalendarManager"
     *       "getUserAuthInstance" → "UserAuthInstance"
     *       "getSystemPasteboard" → "SystemPasteboard"
     */
    private static String extractFactoryReturnClass(String factoryMethodName) {
        if (factoryMethodName == null || factoryMethodName.isEmpty()) {
            return null;
        }
        // Strip "create" or "get" prefix and capitalize
        String prefix = null;
        if (factoryMethodName.startsWith("create") && factoryMethodName.length() > 6) {
            prefix = "create";
        } else if (factoryMethodName.startsWith("get") && factoryMethodName.length() > 3) {
            prefix = "get";
        }
        if (prefix == null) return null;
        String rest = factoryMethodName.substring(prefix.length());
        if (rest.isEmpty()) return null;
        // Capitalize first letter
        return Character.toUpperCase(rest.charAt(0)) + rest.substring(1);
    }

    /**
     * Deterministic indirect call matching using HiAnalyzer's resolved path tokens.
     *
     * HiAnalyzer provides the full resolved path for every call statement, e.g.:
     *   @system:@ohos:account.appAccount.createAppAccountManager.getAllAccounts
     *
     * For indirect rules like AppAccountManager.getAllAccounts, we match by:
     * 1. Method name (last token) must match the rule's method (stripped of args)
     * 2. The token immediately before the method must match either:
     *    a. The rule's namespace directly (e.g., "AppAccountManager")
     *    b. A factory method alias (e.g., "createAppAccountManager" → "AppAccountManager")
     *    c. A known alias from PACKAGE_ALIASES in NamespaceResolver
     * 3. If the rule has parenthesized arguments (e.g., sensor.on('SensorId.X')),
     *    verify the call arguments match.
     */
    private SensitiveApiHit matchDeterministicIndirect(
            Stmt stmt,
            ResolvedNameInfo info,
            String fileName,
            String functionName,
            List<PrivacyApiRuleWithPkg> indirectRules,
            String layer,
            String sourceKind,
            Map<String, String> importAliasMap,
            Set<String> importedSdkModules,
            CallGraph cg
    ) {
        if (!info.valid || info.pathTokens == null || info.pathTokens.isEmpty()) {
            return null;
        }

        String stmtText = safe(stmt);
        boolean assignmentLike = stmtText != null && stmtText.contains("=");

        // Extract Andersen PTA from CallGraph for base variable type checking.
        // Used in the @bundle method-only fallback to reject FPs where an
        // app-internal class has a method name that coincidentally matches
        // a privacy API rule (e.g., app's getAlbums vs PhotoAccessHelper.getAlbums).
        Andersen andersen = null;
        if (cg != null) {
            try {
                andersen = (Andersen) cg.getPta();
            } catch (Throwable ignored) {
                // PTA not available, proceed without base type checking
            }
        }

        SensitiveApiHit bestHit = null;
        int bestScore = Integer.MIN_VALUE;

        for (PrivacyApiRuleWithPkg item : indirectRules) {
            String baseMethod = stripMethodArguments(item.rule.method);

            // 1. Method name must match the last token
            if (!methodMatchesPath(info, baseMethod)) {
                continue;
            }

            // 2. Namespace must match the token before the method, considering aliases
            int methodTokenCount = baseMethod.contains(".") ? baseMethod.split("\\.").length : 1;
            int namespaceIndex = info.pathTokens.size() - methodTokenCount - 1;
            if (namespaceIndex < 0) {
                continue;
            }
            String pathNamespace = info.pathTokens.get(namespaceIndex);

            // Pre-compute rule argument specificity (used in multiple gates below)
            String ruleExpectedArg = extractMethodArgument(item.rule.method);
            boolean hasSpecificArgs = ruleExpectedArg != null;

            boolean nsMatch = false;
            // Direct match
            if (pathNamespace.equals(item.rule.namespace)) {
                nsMatch = true;
            }
            // Factory method alias: createAppAccountManager → AppAccountManager
            if (!nsMatch) {
                String factoryClass = extractFactoryReturnClass(pathNamespace);
                if (factoryClass != null && factoryClass.equals(item.rule.namespace)) {
                    nsMatch = true;
                }
            }
            // Import alias map
            if (!nsMatch && importAliasMap != null) {
                String mapped = importAliasMap.get(pathNamespace);
                if (mapped != null && mapped.equals(item.rule.namespace)) {
                    nsMatch = true;
                }
            }
            // NamespaceResolver PACKAGE_ALIASES
            if (!nsMatch) {
                nsMatch = NamespaceResolver.isAliasCompatible(pathNamespace, item.rule.namespace);
            }
            // moduleAlias from rule
            if (!nsMatch && item.rule.moduleAlias != null) {
                if (pathNamespace.equalsIgnoreCase(item.rule.moduleAlias)) {
                    nsMatch = true;
                }
            }
            // Fuzzy substring match for @bundle/@internal paths where HiAnalyzer
            // maps SDK classes to internal implementation names (e.g.,
            // AVMetadataExtractor → ResumeGenerator, interactiveLiveness → interactivelivenessHsp).
            // SKIP fuzzy match for generic method names (start, getData, etc.) to prevent
            // FPs like UserAuthInstance.start matching timer/player .start() calls.
            // EXCEPTION: allow fuzzy match when the rule has parenthesized arguments
            // (e.g., on('locationChange')), which provide extra specificity.
            if (!nsMatch && item.rule.namespace != null && !item.rule.namespace.isEmpty()
                    && (!GENERIC_METHOD_BLACKLIST.contains(baseMethod.toLowerCase(Locale.ROOT))
                        || hasSpecificArgs)) {
                String nsLower = item.rule.namespace.toLowerCase(Locale.ROOT);
                String pathNsLower = pathNamespace != null ? pathNamespace.toLowerCase(Locale.ROOT) : "";
                // Fuzzy substring match: only when pathNamespace is non-empty and
                // has meaningful length (>= 3 chars). Empty/short pathNamespaces
                // would trivially match any rule namespace via nsLower.contains(""),
                // causing FPs like Map.set("sdkApiVersion", 0) matching deviceinfo.sdkApiVersion.
                if (pathNsLower.length() >= 3
                        && (pathNsLower.contains(nsLower) || nsLower.contains(pathNsLower))) {
                    nsMatch = true;
                }
                // Also check all path tokens for namespace substring — but ONLY for
                // @bundle/@internal paths. For FIELD_MAP (where sourcePrefix is typically
                // an import path like @ohos.deviceInfo), checking all tokens would match
                // any statement in a file that imports the SDK module, even if the
                // receiver variable is unrelated (e.g., Map.set("sdkApiVersion", 0)
                // in a file that also imports @ohos.deviceInfo).
                // IMPORTANT: require the token to END with the rule namespace (not just
                // contain it), to prevent class names like "DeviceInfoPlusOhosPlugin"
                // from matching the rule namespace "deviceinfo" — the plugin class is
                // NOT the same as the @ohos.deviceInfo SDK module.
                if (!nsMatch && ("@bundle".equals(info.sourcePrefix)
                        || "@internal".equals(info.sourcePrefix))) {
                    for (String token : info.pathTokens) {
                        if (token == null) continue;
                        String tokLower = token.toLowerCase(Locale.ROOT);
                        if (tokLower.equals(nsLower) || tokLower.endsWith("." + nsLower)
                                || tokLower.endsWith(":" + nsLower)) {
                            nsMatch = true;
                            break;
                        }
                    }
                }
            }
            // Method-only fallback for @internal/@bundle: if the method name matches
            // exactly and HiAnalyzer deterministically resolved it, accept it.
            // HiAnalyzer's deterministic resolution already confirms the API call.
            // BUT: skip generic method names (start, stop, get, etc.) to avoid FPs
            // on app-internal classes that happen to share method names with SDK APIs.
            // Generic verbs like "start" appear on countless @bundle objects (TimeDownState.start,
            // AudioUtil.audioCapturer.start, etc.) and must not match UserAuthInstance.start.
            //
            // IMPORT GATE: For @bundle (app-internal) calls, verify that the rule's SDK
            // module is actually imported in this abc file. If @ohos.calendar is not
            // imported, Calendar.getEvents is impossible regardless of method name match.
            // This eliminates FPs where app-internal classes have methods that coincidentally
            // share names with privacy APIs (e.g., Flutter's ObservedObject.getEvents vs
            // @ohos.calendar.Calendar.getEvents).
            //
            // NOTE: @internal is NOT gated because HiAnalyzer maps SDK framework calls
            // (e.g., UniApp's DCloudio wrapper invoking @ohos.multimedia.photoAccessHelper)
            // to @internal names. The @ohos.* module may not appear in ForeignClasses when
            // accessed through a framework intermediary, so gating would cause FNs.
            if (!nsMatch && "@bundle".equals(info.sourcePrefix)) {
                if (!GENERIC_METHOD_BLACKLIST.contains(baseMethod.toLowerCase(Locale.ROOT))
                        && isRuleModuleImported(item, importedSdkModules)) {
                    // PTA base-type gate: verify the call's base variable actually
                    // points to a type compatible with the rule's namespace.
                    // Without this, any app-internal class with a method name that
                    // coincidentally matches a privacy API (e.g., getAlbums) would
                    // be falsely accepted as long as the SDK module is imported.
                    // When PTA identifies the base as an app-internal class that
                    // contradicts the rule's namespace, reject the match.
                    boolean ptaContradicts = false;
                    if (andersen != null) {
                        try {
                            Set<String> baseCandidates =
                                    NamespaceResolver.inferNamespaceCandidatesFromCallBase(
                                            stmt, andersen, cg);
                            if (!baseCandidates.isEmpty()
                                    && NamespaceResolver.isNamespaceContradicted(
                                            baseCandidates, item.rule.namespace)) {
                                ptaContradicts = true;
                            }
                        } catch (Throwable ignored) {
                            // PTA query failed, don't block the match
                        }
                    }
                    if (!ptaContradicts) {
                        nsMatch = true;
                    }
                } else if (GENERIC_METHOD_BLACKLIST.contains(baseMethod.toLowerCase(Locale.ROOT))
                        && isRuleModuleImported(item, importedSdkModules)
                        && andersen != null) {
                    // For blacklisted method names on @bundle path, require PTA
                    // confirmation: only accept if PTA resolves the base variable
                    // to a type compatible with the rule's namespace (non-empty
                    // and not contradicted). This prevents FPs where any app-internal
                    // class with a coincidentally-matching method name (e.g.,
                    // getAlbums) is falsely accepted, while still allowing real TPs
                    // where PTA can confirm the receiver is the correct SDK type.
                    try {
                        Set<String> baseCandidates =
                                NamespaceResolver.inferNamespaceCandidatesFromCallBase(
                                        stmt, andersen, cg);
                        if (!baseCandidates.isEmpty()
                                && !NamespaceResolver.isNamespaceContradicted(
                                        baseCandidates, item.rule.namespace)) {
                            nsMatch = true;
                        }
                    } catch (Throwable ignored) {
                        // PTA query failed, don't accept blacklisted method
                    }
                }
            }
            if (!nsMatch && "@internal".equals(info.sourcePrefix)) {
                if (!GENERIC_METHOD_BLACKLIST.contains(baseMethod.toLowerCase(Locale.ROOT))) {
                    nsMatch = true;
                } else if (isRuleModuleImported(item, importedSdkModules)) {
                    // For blacklisted method names (start, getData, etc.), require import gate
                    // even for @internal to prevent FPs where HiAnalyzer maps timer/player
                    // .start() calls to @internal:...UserAuthInstance.start
                    nsMatch = true;
                }
            }

            // Unified PTA gate for generic method names: regardless of which path set
            // nsMatch=true, if the method is in GENERIC_METHOD_BLACKLIST and has no
            // specific arguments, verify via PTA that the call base type is compatible
            // with the rule's namespace. This catches FPs where HiAnalyzer's API_MAP
            // misidentifies an app-internal class (e.g., chart.getData()) as a privacy
            // API class (e.g., SystemPasteboard.getData).
            if (nsMatch
                    && GENERIC_METHOD_BLACKLIST.contains(baseMethod.toLowerCase(Locale.ROOT))
                    && !hasSpecificArgs
                    && andersen != null) {
                try {
                    Set<String> baseCandidates =
                            NamespaceResolver.inferNamespaceCandidatesFromCallBase(
                                    stmt, andersen, cg);
                    if (!baseCandidates.isEmpty()
                            && NamespaceResolver.isNamespaceContradicted(
                                    baseCandidates, item.rule.namespace)) {
                        nsMatch = false;
                    }
                } catch (Throwable ignored) {
                }
            }

            if (!nsMatch) {
                continue;
            }

            // 3. If rule has parenthesized arguments, verify call args
            String expectedArg = ruleExpectedArg;
            if (expectedArg != null) {
                if (!callStmtArgsMatchArgumentPattern(stmt, stmtText, expectedArg)) {
                    continue;
                }
            }

            // Score: prefer longer path token matches (more specific)
            int score = info.pathTokens.size();
            if (expectedArg != null) {
                score += 100;
            }
            if (score > bestScore) {
                bestHit = createBaseHit(
                        stmt, info, fileName, functionName, item, layer, sourceKind);
                bestHit.category = assignmentLike
                        ? "indirect invoke stmt after assignment" : "indirect invoke stmt";
                bestScore = score;
            }
        }

        return bestHit;
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
        List<SensitiveApiHit> hits = matchDirectCallAll(stmt, info, fileName, functionName,
                directRules, layer, sourceKind);
        return hits.isEmpty() ? null : hits.get(0);
    }

    /**
     * Matches a statement against all direct-call rules, returning ALL matching hits.
     * This handles cases where the same API call matches multiple rules with different
     * namespace aliases (e.g., geoLocationManager.getLastLocation and geolocation.getLastLocation).
     */
    private List<SensitiveApiHit> matchDirectCallAll(
            Stmt stmt,
            ResolvedNameInfo info,
            String fileName,
            String functionName,
            List<PrivacyApiRuleWithPkg> directRules,
            String layer,
            String sourceKind
    ) {
        List<SensitiveApiHit> hits = new ArrayList<>();
        if (!info.valid || info.lastToken == null) {
            return hits;
        }

        String stmtText = safe(stmt);
        boolean assignmentLike = stmtText != null && stmtText.contains("=");

        SensitiveApiHit bestHit = null;
        int bestScore = Integer.MIN_VALUE;

        for (PrivacyApiRuleWithPkg item : directRules) {
            // Strip parenthesized arguments from the rule method name.
            String baseMethod = stripMethodArguments(item.rule.method);

            if (!methodMatchesPath(info, baseMethod)
                    || !reviewedNamespaceMatches(info.pathTokens, baseMethod, item.rule)) {
                continue;
            }

            // Empty-namespace rules (e.g., checkSysIntegrity, getSystemInfoSync) represent
            // top-level SDK functions. Reject them when the call is on a @bundle/@internal
            // object — these are app-internal method calls, not top-level function calls.
            if ((item.rule.namespace == null || item.rule.namespace.isEmpty())
                    && ("@bundle".equals(info.sourcePrefix) || "@internal".equals(info.sourcePrefix))) {
                continue;
            }

            // If the rule has parenthesized arguments, verify them via CallStmt argument inspection.
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
            SensitiveApiHit hit = createBaseHit(
                    stmt, info, fileName, functionName, item, layer, sourceKind);
            hit.category = assignmentLike
                    ? "direct invoke stmt after assignment" : "direct invoke stmt";

            // Collect all matching hits (for cross-namespace alias coverage)
            hits.add(hit);

            if (score > bestScore) {
                bestHit = hit;
                bestScore = score;
            }
        }

        // Deduplicate by method name: if multiple namespace aliases match the same
        // stmt+method (e.g., geoLocationManager.getLastLocation vs geolocation.getLastLocation),
        // keep only the first match (the one with the highest score).
        if (hits.size() > 1) {
            Set<String> seenMethods = new HashSet<>();
            List<SensitiveApiHit> deduped = new ArrayList<>();
            for (SensitiveApiHit h : hits) {
                String methodKey = h.method != null ? h.method : "";
                if (seenMethods.add(methodKey)) {
                    deduped.add(h);
                }
            }
            hits = deduped;
        }

        return hits;
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
                    // When the rule has a parenthesized argument pattern (e.g.,
                    // sensor.on('SensorId.ACCELEROMETER')), the argument provides
                    // additional specificity beyond the bare method name "on".
                    // In this case, bypass the generic-method blacklist because the
                    // argument verification (callStmtArgsMatchArgumentPattern) will
                    // disambiguate further downstream.
                    boolean ruleHasParameterizedArgument = extractMethodArgument(item.rule.method) != null;
                    if (GENERIC_METHOD_BLACKLIST.contains(baseMethod.toLowerCase(Locale.ROOT))
                            && !hasPtaCandidates && namespaceCandidates.isEmpty()
                            && !ruleHasParameterizedArgument) {
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

        // @unknown is always rejected regardless of SYSTEM_ONLY_MODE
        if ("@unknown".equals(info.sourcePrefix)) {
            return false;
        }

        // @internal names are rejected unless the last pathToken matches a known
        // privacy API method name. HiAnalyzer sometimes maps SDK classes to internal
        // implementation names (e.g., AVMetadataExtractor → ArkInternal.ResumeGenerator),
        // but the method name (fetchMetadata) remains stable.
        if ("@internal".equals(info.sourcePrefix)) {
            if (info.lastToken != null) {
                String lastStripped = stripMethodArguments(info.lastToken).toLowerCase(Locale.ROOT);
                for (PrivacyApiRuleWithPkg rule : directRulesCache) {
                    if (stripMethodArguments(rule.rule.method).toLowerCase(Locale.ROOT).equals(lastStripped)) {
                        return true;
                    }
                }
                for (PrivacyApiRuleWithPkg rule : indirectRulesCache) {
                    if (stripMethodArguments(rule.rule.method).toLowerCase(Locale.ROOT).equals(lastStripped)) {
                        return true;
                    }
                }
                for (PrivacyApiRuleWithPkg rule : constantRulesCache) {
                    if (stripMethodArguments(rule.rule.method).toLowerCase(Locale.ROOT).equals(lastStripped)) {
                        return true;
                    }
                }
            }
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
            // Check if the last pathToken matches a known privacy API method name
            // (direct, indirect, or constant rules)
            if (info.lastToken != null) {
                String lastStripped = stripMethodArguments(info.lastToken).toLowerCase(Locale.ROOT);
                for (PrivacyApiRuleWithPkg rule : indirectRulesCache) {
                    String ruleMethod = stripMethodArguments(rule.rule.method).toLowerCase(Locale.ROOT);
                    if (lastStripped.equals(ruleMethod)) {
                        return true;
                    }
                }
                for (PrivacyApiRuleWithPkg rule : directRulesCache) {
                    String ruleMethod = stripMethodArguments(rule.rule.method).toLowerCase(Locale.ROOT);
                    if (lastStripped.equals(ruleMethod)) {
                        return true;
                    }
                }
                for (PrivacyApiRuleWithPkg rule : constantRulesCache) {
                    String ruleMethod = stripMethodArguments(rule.rule.method).toLowerCase(Locale.ROOT);
                    if (lastStripped.equals(ruleMethod)) {
                        return true;
                    }
                }
            }
            return false;
        }

        // @import names are accepted only when the import path contains an SDK
        // qualifier (@ohos: or @kit:). Third-party imports (e.g., @dcloudio.*)
        // may export functions with the same name as privacy APIs (e.g.,
        // getSystemInfoSync) but they are NOT HarmonyOS system API calls.
        if ("@import".equals(info.sourcePrefix)) {
            if (SYSTEM_ONLY_MODE) {
                return false;
            }
            String body = info.rawBody != null ? info.rawBody : "";
            return body.contains("@ohos:") || body.contains("@kit:");
        }

        return "@system".equals(info.sourcePrefix);
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

        // Strategy 1: Direct StringConstant in CallStmt arguments
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
                // Fall through to def-use backtracking
            }
        }

        // Strategy 2: Def-use backtracking on function body — trace FIRST argument only.
        // Walk backwards from the call stmt to find how the first Local argument was assigned.
        // This resolves:
        //   - StringConstant assignments: v9 = "locationError"; v6 = v9; → arg="locationError"
        //   - Enum field access chains: v8 = v8.<SensorId>; v8 = v8.<ACCELEROMETER>; v6 = v8; → arg="ACCELEROMETER"
        //   - Enum field access: v6 = v8.<HEART_RATE>; → arg="HEART_RATE"
        Set<String> resolvedArgValues = resolveCallArgumentsViaDefUse(stmt);
        if (!resolvedArgValues.isEmpty()) {
            // Strategy 2 resolved the first argument — trust this result.
            // If it doesn't match, the argument is a different value (e.g., "locationError"
            // vs expected "locationChange"), so we should NOT fall through to Strategies 3/4
            // which could pick up values from other call sites in the same function.
            for (String val : resolvedArgValues) {
                if (argumentMatchesPattern(val, expectedArg)) {
                    return true;
                }
            }
            return false;
        }

        // Strategy 3: Fallback - check stmtText for the expected argument pattern
        // Only reached when Strategy 2 could NOT resolve the first argument (e.g., the
        // argument is not a Local variable, or its def-use chain couldn't be traced).
        String argTail = expectedArg.contains(".") ? expectedArg.substring(expectedArg.lastIndexOf('.') + 1) : expectedArg;
        if (stmtText == null) return false;
        if (stmtText.contains(expectedArg)) return true;
        if (argTail.length() >= 3 && stmtText.contains(argTail)) return true;

        // Strategy 4: Check preceding statements in the function body for enum field access
        // patterns like v8.<ACCELEROMETER> that match the expected argument tail
        // Only reached when Strategy 2 failed to resolve AND Strategy 3 didn't match.
        if (argTail.length() >= 3) {
            Set<String> bodyArgValues = resolveEnumAccessFromFunctionBody(stmt, argTail);
            for (String val : bodyArgValues) {
                if (argumentMatchesPattern(val, expectedArg)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Resolves call argument values by walking backwards through the function body
     * to find assignments to Local variables used as arguments.
     *
     * Handles two patterns observed in ABC bytecode:
     * 1. StringConstant assignment: v9 = "locationError"; v6 = v9; → resolves "locationError"
     * 2. Enum field access: v8 = v8.<ACCELEROMETER>; v6 = v8; → resolves "ACCELEROMETER"
     *
     * @param callStmt The CallStmt whose arguments need resolution
     * @return Set of resolved string values from argument def-use chains
     */
    private Set<String> resolveCallArgumentsViaDefUse(Stmt callStmt) {
        Set<String> resolved = new HashSet<>();
        if (!(callStmt instanceof CallStmt)) {
            return resolved;
        }

        try {
            CallStmt cs = (CallStmt) callStmt;
            var callExpr = cs.getCallExpr();
            if (callExpr == null) return resolved;
            var argList = callExpr.getArgList();
            if (argList == null) return resolved;

            // Collect Local argument names to trace, preserving order for per-arg tracking
            List<String> argLocalNameList = new ArrayList<>();
            Set<String> argLocalNames = new HashSet<>();
            for (Object arg : argList) {
                if (arg instanceof com.huawei.hianalyzer.ir.value.Local) {
                    String name = ((com.huawei.hianalyzer.ir.value.Local) arg).getName();
                    if (name != null && !argLocalNames.contains(name)) {
                        argLocalNames.add(name);
                        argLocalNameList.add(name);
                    }
                }
            }

            // Also parse argument variable names from the call statement text.
            // Local.getName() may return truncated names (e.g., "v" instead of "v6"),
            // but the statement text contains the full indexed names like "v6", "v7".
            // Example call text: "v9 = VirtualCall: v5.<on>(v6, v7)"
            String callText = callStmt.toString();
            if (callText != null) {
                int parenStart = callText.indexOf('(');
                int parenEnd = callText.lastIndexOf(')');
                if (parenStart >= 0 && parenEnd > parenStart) {
                    String argsStr = callText.substring(parenStart + 1, parenEnd);
                    for (String token : argsStr.split(",")) {
                        token = token.trim();
                        if (token.matches("v\\d+") && !argLocalNames.contains(token)) {
                            argLocalNames.add(token);
                            argLocalNameList.add(token);
                        }
                    }
                }
            }
            if (argLocalNames.isEmpty()) return resolved;

            // Get the function body
            HiFunction func = ScannerUtils.safeGetHiFunction(callStmt);
            if (func == null) return resolved;
            com.huawei.hianalyzer.ir.Body body = func.getBody();
            if (body == null) return resolved;
            var stmts = body.getStmts();
            if (stmts == null) return resolved;

            // Find the call stmt index
            int callIdx = -1;
            for (int i = 0; i < stmts.size(); i++) {
                if (stmts.get(i) == callStmt) {
                    callIdx = i;
                    break;
                }
            }
            if (callIdx < 0) return resolved;

            // Only trace the FIRST argument — the expected pattern (e.g., 'locationChange')
            // is always the first parameter to methods like on(), off(), subscribe().
            // Tracing ALL arguments causes FP when a later argument's def-use chain
            // happens to resolve to the expected value from a different code path.
            // Example FP: on("locationError", callback) matches rule on('locationChange')
            // because the callback variable's def-use chain reaches "locationChange"
            // from an earlier on("locationChange", ...) call in the same function.
            //
            // Parse the first argument variable name directly from the call text
            // (not from argLocalNameList) because:
            // 1. Local.getName() may return truncated names (e.g., "v" instead of "v6")
            // 2. argList may include the receiver object as the first element
            // The call text format is: "vN = VirtualCall: vM.<method>(v1, v2, ...)"
            // so the first token inside parentheses is the first actual argument.
            String firstArgVar = null;
            if (callText != null) {
                int parenStart = callText.indexOf('(');
                int parenEnd = callText.lastIndexOf(')');
                if (parenStart >= 0 && parenEnd > parenStart) {
                    String argsStr = callText.substring(parenStart + 1, parenEnd);
                    String[] tokens = argsStr.split(",");
                    if (tokens.length > 0) {
                        String firstToken = tokens[0].trim();
                        if (firstToken.matches("v\\d+")) {
                            firstArgVar = firstToken;
                        }
                    }
                }
            }
            // Fallback: if call text parsing fails, use argLocalNameList
            if (firstArgVar == null && !argLocalNameList.isEmpty()) {
                firstArgVar = argLocalNameList.get(0);
            }
            int lookBack = Math.min(50, callIdx);
            if (firstArgVar != null) {
                Set<String> argResolved = traceVariableDefUse(firstArgVar, stmts, callIdx, lookBack, 0);
                resolved.addAll(argResolved);
            }
        } catch (Throwable ignored) {
            // Non-fatal: just return what we have
        }

        return resolved;
    }

    /** Pattern for: vN = "stringValue" */
    private static final java.util.regex.Pattern STRING_ASSIGN_PATTERN =
            java.util.regex.Pattern.compile("(v\\d+)\\s*=\\s*\"([^\"]+)\"");

    /** Pattern for: vN = vM.<fieldAccess> (enum property access like v8.<ACCELEROMETER>) */
    private static final java.util.regex.Pattern ENUM_ASSIGN_PATTERN =
            java.util.regex.Pattern.compile("(v\\d+)\\s*=\\s*v\\d+\\.<(\\w+)>");

    /**
     * Checks if a variable name is reachable from any of the target argument names
     * via a chain of copy assignments (vN = vM).
     */
    private boolean isReachableViaCopy(Set<String> targetNames, String varName,
                                        List<Stmt> stmts, int callIdx, int fromIdx) {
        if (targetNames.contains(varName)) return true;
        // Simple 1-level copy check: target = varName
        for (int i = fromIdx + 1; i < callIdx && i < fromIdx + 5; i++) {
            String s = stmts.get(i) != null ? stmts.get(i).toString() : null;
            if (s == null) continue;
            java.util.regex.Matcher copyMatcher = COPY_PATTERN.matcher(s);
            if (copyMatcher.find()) {
                String dst = copyMatcher.group(1);
                String src = copyMatcher.group(2);
                if (src.equals(varName) && targetNames.contains(dst)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Pattern for: vN = vM (simple copy) */
    private static final java.util.regex.Pattern COPY_PATTERN =
            java.util.regex.Pattern.compile("(v\\d+)\\s*=\\s*(v\\d+)\\s*$");

    /**
     * Recursively traces the def-use chain of a variable backwards from the call site.
     *
     * For each argument variable, finds its most recent assignment before the call.
     * If that assignment is a string constant or enum field access, returns the value.
     * If it's a copy (vN = vM), recursively traces vM's most recent assignment before
     * the copy point. This correctly handles variable reuse in SSA-untransformed IR:
     *
     *   [91] v5 = "locationChange"     ← v5's 1st assignment
     *   [92] v2 = v5                    ← v2 gets "locationChange"
     *   [103] v5 = <HIGH_POWER_CONSUMPTION>  ← v5's 2nd assignment (reuse!)
     *   [108] call(v2, v3, v4)          ← v2 should resolve to "locationChange"
     *
     * @param varName   The variable to trace (e.g., "v2")
     * @param stmts     The function body statements
     * @param beforeIdx Trace assignments before this index (exclusive)
     * @param maxLookBack Maximum statements to look back
     * @param depth     Recursion depth (max 3 to prevent infinite loops)
     * @return Set of resolved string/enum values for this variable
     */
    private Set<String> traceVariableDefUse(String varName, List<Stmt> stmts,
                                            int beforeIdx, int maxLookBack, int depth) {
        Set<String> resolved = new HashSet<>();
        if (depth > 3 || varName == null) return resolved;

        int start = Math.max(0, beforeIdx - maxLookBack);
        // Find the NEAREST assignment to varName before beforeIdx
        for (int i = beforeIdx - 1; i >= start; i--) {
            String s = stmts.get(i) != null ? stmts.get(i).toString() : null;
            if (s == null) continue;

            // Check if this statement assigns to varName
            // Pattern: varName = "string"
            java.util.regex.Matcher strMatcher = STRING_ASSIGN_PATTERN.matcher(s);
            if (strMatcher.find() && strMatcher.group(1).equals(varName)) {
                resolved.add(strMatcher.group(2));
                return resolved;
            }

            // Pattern: varName = vM.<ENUM_VALUE>
            java.util.regex.Matcher enumMatcher = ENUM_ASSIGN_PATTERN.matcher(s);
            if (enumMatcher.find() && enumMatcher.group(1).equals(varName)) {
                resolved.add(enumMatcher.group(2));
                return resolved;
            }

            // Pattern: varName = vM (copy)
            java.util.regex.Matcher copyMatcher = COPY_PATTERN.matcher(s);
            if (copyMatcher.find() && copyMatcher.group(1).equals(varName)) {
                String srcVar = copyMatcher.group(2);
                // Recursively trace the source variable, looking back from the copy point
                Set<String> srcResolved = traceVariableDefUse(srcVar, stmts, i, maxLookBack, depth + 1);
                resolved.addAll(srcResolved);
                return resolved;
            }
        }
        return resolved;
    }

    /**
     * Scans the function body for enum field access patterns that match the expected argument tail.
     * This is a last-resort fallback that looks for patterns like v8.<ACCELEROMETER> anywhere
     * in the function body before the call statement.
     */
    private Set<String> resolveEnumAccessFromFunctionBody(Stmt callStmt, String expectedTail) {
        Set<String> resolved = new HashSet<>();
        try {
            HiFunction func = ScannerUtils.safeGetHiFunction(callStmt);
            if (func == null) return resolved;
            com.huawei.hianalyzer.ir.Body body = func.getBody();
            if (body == null) return resolved;
            var stmts = body.getStmts();
            if (stmts == null) return resolved;

            int callIdx = -1;
            for (int i = 0; i < stmts.size(); i++) {
                if (stmts.get(i) == callStmt) {
                    callIdx = i;
                    break;
                }
            }
            if (callIdx < 0) return resolved;

            // Scan backwards from call for any vN.<EXPECTED_TAIL> pattern
            for (int i = callIdx - 1; i >= 0 && i >= callIdx - 20; i--) {
                String s = stmts.get(i) != null ? stmts.get(i).toString() : null;
                if (s == null) continue;
                // Look for vN.<EXPECTED_TAIL> pattern
                if (s.contains("<" + expectedTail + ">")) {
                    resolved.add(expectedTail);
                    break;
                }
            }
        } catch (Throwable ignored) {
            // Non-fatal
        }
        return resolved;
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
        // Fuzzy @bundle match: when the method matches exactly but the namespace doesn't
        // match the strict path position, check if any path token contains the namespace
        // as a case-insensitive substring. This handles HMS bundle paths like
        // "interactivelivenessHsp.Index.startLivenessDetection" matching rule namespace
        // "interactiveLiveness" + method "startLivenessDetection".
        if (rule.namespace != null && !rule.namespace.isEmpty() && pathTokens != null) {
            String baseMethodStripped = stripMethodArguments(baseMethod);
            int methodTokenCount = baseMethodStripped != null && baseMethodStripped.contains(".")
                    ? baseMethodStripped.split("\\.").length : 1;
            int methodIdx = pathTokens.size() - methodTokenCount;
            if (methodIdx >= 0) {
                boolean methodMatches = baseMethodStripped.equals(pathTokens.get(methodIdx));
                if (methodMatches) {
                    String nsLower = rule.namespace.toLowerCase(Locale.ROOT);
                    for (String token : pathTokens) {
                        if (token != null && token.toLowerCase(Locale.ROOT).contains(nsLower)) {
                            return true;
                        }
                    }
                }
            }
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
