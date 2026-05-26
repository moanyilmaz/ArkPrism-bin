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

            List<SensitiveApiHit> hits = scanHiFile(
                    hiFile,
                    abcFile.getName(),
                    directRules,
                    indirectRules,
                    constantRules
            );
            Logger.log("    [*] V1 raw hits: " + hits.size());

            if (hits.isEmpty()) {
                Logger.log("[-] No sensitive API hits in current ABC.");
                continue;
            }

            Logger.log("[+] Current ABC sensitive API hits: " + hits.size());

            // Deduplicate ApiUsage objects to avoid duplicates from multiple detection passes
            List<UnifiedPrivacyReport.ApiUsage> dedupedUsages = new ArrayList<>();
            Set<String> seenUsageKeys = new HashSet<>();

            Map<Stmt, Integer> sourceStmtToApiUsageIndex = new LinkedHashMap<>();
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
                }
            }

            for (UnifiedPrivacyReport.ApiUsage usage : dedupedUsages) {
                result.arktsApiUsages.add(usage);

                int usageIndex = nextApiUsageIndex++;
                // Find the corresponding hit for BODY_HIT layer
                for (SensitiveApiHit hit : hits) {
                    if ("BODY_HIT".equals(hit.layer) && hit.stmtObj != null) {
                        String hitKey = (hit.stmtText != null ? hit.stmtText : "")
                                + "|" + (hit.function != null ? hit.function : "");
                        String usageKey = (usage.code != null ? usage.code : "")
                                + "|" + (usage.declaringMethod != null ? usage.declaringMethod : "");
                        if (hitKey.equals(usageKey)) {
                            sourceStmtToApiUsageIndex.put(hit.stmtObj, usageIndex);
                            sinkStmts.add(hit.stmtObj);
                            break;
                        }
                    }
                }
            }

            if (sinkStmts.isEmpty()) {
                Logger.log("[-] Current ABC has only CHAIN_EVIDENCE hits, no BODY_HIT, skipping call chain.");
                continue;
            }

            buildCallChainsForFile(
                    hiFile,
                    abcFile,
                    sinkStmts,
                    sourceStmtToApiUsageIndex,
                    ruleJsonFile,
                    result.callChains,
                    result.warnings
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

    private void buildCallChainsForFile(
            HiFile hiFile,
            File abcFile,
            Set<Stmt> sinkStmts,
            Map<Stmt, Integer> sourceStmtToApiUsageIndex,
            File ruleJsonFile,
            List<UnifiedPrivacyReport.CallChainReport> outputChains,
            List<String> warnings
    ) {
        CallGraph cg = null;

        try {
            Logger.log("[*] Building call graph with ANDERSEN...");
            cg = Stage.createCallGraph(hiFile, CallGraph.CGBuildMethod.ANDERSEN, true);
        } catch (Throwable t) {
            String msg = "Call graph construction failed for " + abcFile.getAbsolutePath() + ": " + t.getMessage();
            warnings.add(msg);
            Logger.error("[-] " + msg);
        }

        if (cg == null) {
            return;
        }

        List<CallGraphExplorer.CallChain> chains;
        try {
            chains = CallGraphExplorer.extractPrivacyCallChains(hiFile, cg, sinkStmts);
        } catch (Throwable t) {
            String msg = "Call chain extraction failed for " + abcFile.getAbsolutePath() + ": " + t.getMessage();
            warnings.add(msg);
            Logger.error("[-] " + msg);
            return;
        }

        Logger.log("[+] Call chain extraction complete: " + chains.size());

        Map<Stmt, List<CallStmt>> dataFlowResults = new HashMap<>();
        try {
            Logger.log("[*] Attempting forward data flow analysis...");
            dataFlowResults = DataFlowExplorer.findDataSinks(hiFile, cg, sinkStmts,
                    ruleJsonFile != null ? ruleJsonFile.getAbsolutePath() : null);
        } catch (Throwable t) {
            String msg = "Data flow analysis skipped for " + abcFile.getAbsolutePath() + ": " + t.getMessage();
            warnings.add(msg);
            Logger.error("[-] " + msg);
        }

        for (Stmt sourceStmt : sinkStmts) {
            Integer apiUsageIndex = sourceStmtToApiUsageIndex.get(sourceStmt);
            if (apiUsageIndex == null) {
                continue;
            }

            HiFunction sourceFunc = safeGetHiFunction(sourceStmt);
            if (sourceFunc == null) {
                continue;
            }

            List<CallGraphExplorer.CallChain> relatedChains = chains.stream()
                    .filter(c -> c != null && c.sinkNode != null && c.sinkNode.equals(sourceFunc))
                    .collect(Collectors.toList());

            if (relatedChains.isEmpty()) {
                UnifiedPrivacyReport.CallChainReport fallback = buildFallbackChainReport(
                        apiUsageIndex,
                        abcFile,
                        sourceStmt,
                        sourceFunc,
                        dataFlowResults.getOrDefault(sourceStmt, new ArrayList<>()),
                        hiFile
                );
                outputChains.add(fallback);
                continue;
            }

            for (CallGraphExplorer.CallChain chain : relatedChains) {
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
            List<PrivacyApiRuleWithPkg> constantRules
    ) {
        List<SensitiveApiHit> results = new ArrayList<>();

        Map<Stmt, String> stmtApiMap = safeGetAllStmtApiNameMap(hiFile);
        Map<Stmt, String> stmtFieldMap = safeGetAllStmtFieldNameMap(hiFile);

        for (Map.Entry<Stmt, String> entry : stmtApiMap.entrySet()) {
            Stmt stmt = entry.getKey();
            String fullApiName = normalizeFullName(entry.getValue());
            String stmtText = safe(stmt);

            if (stmt == null || fullApiName == null || fullApiName.isEmpty()) {
                continue;
            }

            // Skip SSA phi/copy nodes: "vN = vN.<method>" where LHS == RHS variable
            if (isSsaPhiNode(stmtText)) {
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
                continue;
            }

            SensitiveApiHit indirectHit = matchIndirectCall(
                    stmt, info, fileName, functionName, indirectRules, "BODY_HIT", "API_MAP"
            );
            if (indirectHit != null) {
                results.add(indirectHit);
            }
        }

        for (Map.Entry<Stmt, String> entry : stmtFieldMap.entrySet()) {
            Stmt stmt = entry.getKey();
            String fullFieldName = normalizeFullName(entry.getValue());

            if (stmt == null || fullFieldName == null || fullFieldName.isEmpty()) {
                continue;
            }

            ResolvedNameInfo info = parseResolvedName(fullFieldName);
            if (!isAcceptedResolvedName(info)) {
                continue;
            }

            HiFunction func = safeGetHiFunction(stmt);
            String functionName = safeFunctionName(func);

            SensitiveApiHit fieldHit = matchPrivacyConstant(
                    stmt, info, fileName, functionName, constantRules, "BODY_HIT", "FIELD_MAP"
            );
            if (fieldHit != null) {
                results.add(fieldHit);
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
                    stmt, info, fileName, functionName, indirectRules, "CHAIN_EVIDENCE", "FIELD_MAP"
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

        for (PrivacyApiRuleWithPkg item : directRules) {
            if (!Objects.equals(item.rule.method, info.lastToken)
                    || !namespaceMustBePredecessor(info.pathTokens, item.rule.namespace)) {
                continue;
            }

            SensitiveApiHit hit = createBaseHit(stmt, info, fileName, functionName, item, layer, sourceKind);
            hit.category = assignmentLike ? "direct invoke stmt after assignment" : "direct invoke stmt";
            return hit;
        }

        return null;
    }

    private SensitiveApiHit matchIndirectCall(
            Stmt stmt,
            ResolvedNameInfo info,
            String fileName,
            String functionName,
            List<PrivacyApiRuleWithPkg> indirectRules,
            String layer,
            String sourceKind
    ) {
        if (!info.valid || info.pathTokens == null || info.pathTokens.isEmpty()) {
            return null;
        }

        String joinedPath = String.join(".", info.pathTokens);

        for (PrivacyApiRuleWithPkg item : indirectRules) {
            if (item.rule.method == null
                    || item.rule.method.isEmpty()
                    || !endsWithDotted(joinedPath, item.rule.method)
                    || !namespaceMustBePredecessor(info.pathTokens, item.rule.namespace)) {
                continue;
            }

            SensitiveApiHit hit = createBaseHit(stmt, info, fileName, functionName, item, layer, sourceKind);
            hit.category = "indirect invoke";
            return hit;
        }

        return null;
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
            if (!Objects.equals(item.rule.method, info.lastToken)
                    || !namespaceMustBePredecessor(info.pathTokens, item.rule.namespace)) {
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
                || "@internal".equals(info.sourcePrefix)
                || "@bundle".equals(info.sourcePrefix)) {
            return false;
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