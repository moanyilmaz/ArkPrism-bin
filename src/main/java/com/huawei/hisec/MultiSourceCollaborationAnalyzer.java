package com.huawei.hisec;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.base.HiFunction;
import com.huawei.hianalyzer.analysis.graph.callgraph.CallGraph;
import com.huawei.hianalyzer.ir.stmt.CallStmt;

import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * Multi-Source Collaboration Analyzer.
 *
 * Current version: rule-driven same-method matching.
 *
 * Logic:
 * 1. Only analyze API hits with sourceLayer == "ArkTS";
 * 2. Native/.so does not participate;
 * 3. Read combination rules from profile_combinations.json;
 * 4. If requiredApis of a combination rule are satisfied within the same method, output multiSourceCollaboration;
 * 5. Does not determine "how risky a combination is"; riskLevel only passes through the rule file field.
 */
public class MultiSourceCollaborationAnalyzer {

    private static final String DEFAULT_RULE_FILE = "config/profile_combinations.json";
    private static final String DEFAULT_SCOPE = "same_method";

    /**
     * Keep Main.java existing call unchanged:
     *
     *     MultiSourceCollaborationAnalyzer.analyze(report)
     *
     * Reads profile_combinations.json from config/ by default.
     */
    public static List<UnifiedPrivacyReport.MultiSourceCollaboration> analyze(
            UnifiedPrivacyReport report
    ) {
        return analyze(report, new File(DEFAULT_RULE_FILE));
    }

    /**
     * Call this overload if Main.java supports a fourth parameter in the future.
     */
    public static List<UnifiedPrivacyReport.MultiSourceCollaboration> analyze(
            UnifiedPrivacyReport report,
            File ruleFile
    ) {
        return analyze(report, ruleFile, null);
    }

    /**
     * Full analysis with HiFile, supports CallGraph-based LCA detection.
     *
     * @param report  Analysis report
     * @param ruleFile Combination rule file
     * @param hiFile   HiFile parsed by Huawei tool (for building CallGraph)
     */
    public static List<UnifiedPrivacyReport.MultiSourceCollaboration> analyze(
            UnifiedPrivacyReport report,
            File ruleFile,
            HiFile hiFile
    ) {
        List<UnifiedPrivacyReport.MultiSourceCollaboration> results = new ArrayList<>();

        if (report == null || report.privacyApiUsages == null || report.privacyApiUsages.isEmpty()) {
            return results;
        }

        List<ProfileCombinationRule> rules = loadRules(ruleFile);
        if (rules.isEmpty()) {
            Logger.log("[MultiSource] no profile combination rules loaded; skip collaboration detection.");
            return results;
        }

        // Build CallGraph (if HiFile is provided)
        CallGraph callGraph = buildCallGraph(hiFile);

        results.addAll(analyzeSameMethodByRules(report, rules));
        results.addAll(analyzeLcaByRules(report, rules, callGraph));
        results.addAll(analyzeSameFileByRules(report, rules));

        return results;
    }

    /**
     * Build CallGraph.
     * Uses Huawei tool's CHA (Class Hierarchy Analysis) to build call graph.
     */
    private static CallGraph buildCallGraph(HiFile hiFile) {
        if (hiFile == null) {
            return null;
        }

        try {
            // Use CHA to build call graph (fast but conservative)
            return CallGraph.createCHAGraph(hiFile);
        } catch (Throwable t) {
            Logger.error("[MultiSource] Failed to build CallGraph: " + t.getMessage());
            return null;
        }
    }

    // ======================================================
    // 1. same-method Rule Matching
    // ======================================================

    private static List<UnifiedPrivacyReport.MultiSourceCollaboration> analyzeSameMethodByRules(
            UnifiedPrivacyReport report,
            List<ProfileCombinationRule> rules
    ) {
        List<UnifiedPrivacyReport.MultiSourceCollaboration> results = new ArrayList<>();

        Map<String, List<CandidateApi>> methodToApis = collectArkTsApisByMethod(report);
        Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex = buildCallChainIndex(report);

        Set<String> emittedKeys = new LinkedHashSet<>();

        for (Map.Entry<String, List<CandidateApi>> entry : methodToApis.entrySet()) {
            String declaringMethod = entry.getKey();
            List<CandidateApi> methodApis = deduplicateApis(entry.getValue());

            for (ProfileCombinationRule rule : rules) {
                if (!isSameMethodRule(rule)) {
                    continue;
                }

                List<CandidateApi> matchedApis = matchRuleInMethod(rule, methodApis);
                if (matchedApis.size() < 2) {
                    continue;
                }

                String emitKey = safe(rule.ruleId) + "|" + declaringMethod;
                if (emittedKeys.contains(emitKey)) {
                    continue;
                }
                emittedKeys.add(emitKey);

                UnifiedPrivacyReport.MultiSourceCollaboration collab =
                        buildRuleMatchedCollaboration(
                                rule,
                                declaringMethod,
                                matchedApis,
                                chainByApiIndex
                        );

                results.add(collab);
            }
        }

        return results;
    }

// ======================================================
// 1.1 LCA Rule Matching (Based on CallGraph Reachability)
// ======================================================

    /**
     * LCA detection based on Huawei CallGraph.
     *
     * Improvements:
     * 1. Use CallGraph.getCallersByCallee() to get real call relationships, no longer relying on string path matching
     * 2. BFS from entry functions to find lowest common ancestor
     * 3. Verify that the common ancestor is reachable from both source functions
     *
     * Huawei tool API:
     * - CallGraph.createCHAGraph(hiFile) builds call graph
     * - getCallersByCallee(func) gets functions that call func
     * - getCalleesByCaller(func) gets functions called by func
     * - getEntryFunctions() gets entry functions
     */
    private static List<UnifiedPrivacyReport.MultiSourceCollaboration> analyzeLcaByRules(
            UnifiedPrivacyReport report,
            List<ProfileCombinationRule> rules,
            CallGraph callGraph
    ) {
        List<UnifiedPrivacyReport.MultiSourceCollaboration> results = new ArrayList<>();

        Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex = buildCallChainIndex(report);

        // Collect API hits by method
        Map<String, List<CandidateApi>> methodToApis = collectArkTsApisByMethod(report);

        for (ProfileCombinationRule rule : rules) {
            if (!isLcaRule(rule)) {
                continue;
            }

            // Find all methods that satisfy the rule
            List<CandidateApi> allMatchedApis = new ArrayList<>();
            Map<String, List<CandidateApi>> matchedMethodToApis = new LinkedHashMap<>();

            for (Map.Entry<String, List<CandidateApi>> entry : methodToApis.entrySet()) {
                String method = entry.getKey();
                List<CandidateApi> matchedApis = matchRuleInMethod(rule, entry.getValue());

                if (matchedApis.size() >= 2) {
                    matchedMethodToApis.put(method, matchedApis);
                    allMatchedApis.addAll(matchedApis);
                }
            }

            // Need at least two different methods
            if (matchedMethodToApis.size() < 2) {
                continue;
            }

            // Find LCA based on CallGraph
            if (callGraph != null) {
                CGResult cgResult = findLowestCommonAncestorByCG(
                        callGraph,
                        new ArrayList<>(matchedMethodToApis.keySet())
                );

                if (cgResult != null && cgResult.lca != null) {
                    // Verify reachability using CallGraph
                    List<CandidateApi> reachableApis = verifyReachability(
                            callGraph, cgResult.lca, matchedMethodToApis
                    );

                    if (reachableApis.size() >= 2) {
                        UnifiedPrivacyReport.MultiSourceCollaboration collab =
                                buildCgLcaCollaboration(
                                        rule,
                                        cgResult.lca,
                                        cgResult.lcaSig,
                                        reachableApis,
                                        chainByApiIndex
                                );
                        results.add(collab);
                    }
                }
            }

            // Fallback to path matching if no CallGraph or CG not found
            if (results.isEmpty() || results.get(results.size() - 1).ruleId != rule.ruleId) {
                List<UnifiedPrivacyReport.MultiSourceCollaboration> fallbackResults =
                        analyzeLcaByPath(report, rule, matchedMethodToApis, chainByApiIndex);
                results.addAll(fallbackResults);
            }
        }

        return results;
    }

    /**
     * CallGraph analysis result
     */
    private static class CGResult {
        HiFunction lca;           // LCA function object
        String lcaSig;            // LCA function signature
        int depth;                // LCA depth
    }

    /**
     * Find lowest common ancestor based on CallGraph.
     *
     * Algorithm:
     * 1. BFS from entry functions, collect all reachable functions and their depths
     * 2. For each target function, reverse BFS (using getCallersByCallee) to root
     * 3. Find the nearest common ancestor
     */
    private static CGResult findLowestCommonAncestorByCG(
            CallGraph callGraph,
            List<String> targetMethods
    ) {
        if (callGraph == null || targetMethods == null || targetMethods.size() < 2) {
            return null;
        }

        // Parse target function signatures
        List<HiFunction> targetFuncs = new ArrayList<>();
        for (String methodSig : targetMethods) {
            HiFunction func = resolveFunction(callGraph, methodSig);
            if (func != null) {
                targetFuncs.add(func);
            }
        }

        if (targetFuncs.size() < 2) {
            return null;
        }

        // Build function signature to function mapping
        Map<String, HiFunction> sigToFunc = new HashMap<>();
        for (HiFunction func : targetFuncs) {
            sigToFunc.put(safeFunctionSig(func), func);
        }

        // Step 1: BFS from entry functions, collect all reachable functions and their depths
        Map<HiFunction, Integer> depthFromRoot = new HashMap<>();
        Set<HiFunction> visited = new HashSet<>();
        Deque<HiFunction> queue = new ArrayDeque<>();

        for (HiFunction entry : callGraph.getEntryFunctions()) {
            depthFromRoot.put(entry, 0);
            queue.add(entry);
            visited.add(entry);
        }

        // BFS collect depth
        int maxDepth = 0;
        while (!queue.isEmpty()) {
            HiFunction current = queue.poll();
            int depth = depthFromRoot.get(current);

            for (HiFunction callee : callGraph.getCalleesByCaller(current)) {
                if (callee != null && !visited.contains(callee)) {
                    visited.add(callee);
                    int newDepth = depth + 1;
                    depthFromRoot.put(callee, newDepth);
                    maxDepth = Math.max(maxDepth, newDepth);
                    queue.add(callee);
                }
            }
        }

        // Step 2: Reverse BFS from each target function to root, build ancestor chain
        List<Set<HiFunction>> ancestorSets = new ArrayList<>();
        Map<HiFunction, Integer> depthFromTarget = new HashMap<>();

        for (HiFunction target : targetFuncs) {
            Set<HiFunction> ancestors = new HashSet<>();
            Deque<HiFunction> bfsQueue = new ArrayDeque<>();
            bfsQueue.add(target);
            ancestors.add(target);
            depthFromTarget.put(target, 0);

            int depth = 0;
            while (!bfsQueue.isEmpty()) {
                int size = bfsQueue.size();
                for (int i = 0; i < size; i++) {
                    HiFunction current = bfsQueue.poll();
                    for (HiFunction caller : callGraph.getCallersByCallee(current)) {
                        if (caller != null && !ancestors.contains(caller)) {
                            ancestors.add(caller);
                            bfsQueue.add(caller);
                            depthFromTarget.put(caller, depth + 1);
                        }
                    }
                }
                depth++;
            }

            ancestorSets.add(ancestors);
        }

        // Step 3: Find lowest common ancestor
        // Iterate from shallow to deep, find the first common ancestor shared by all target functions
        for (int depth = 0; depth <= maxDepth; depth++) {
            for (HiFunction candidate : depthFromRoot.keySet()) {
                if (depthFromRoot.get(candidate) != depth) {
                    continue;
                }

                boolean isAncestorOfAll = true;
                for (Set<HiFunction> ancestors : ancestorSets) {
                    if (!ancestors.contains(candidate)) {
                        isAncestorOfAll = false;
                        break;
                    }
                }

                if (isAncestorOfAll) {
                    CGResult result = new CGResult();
                    result.lca = candidate;
                    result.lcaSig = safeFunctionSig(candidate);
                    result.depth = depth;
                    return result;
                }
            }
        }

        return null;
    }

    /**
     * Verify reachability from LCA to each target function.
     */
    private static List<CandidateApi> verifyReachability(
            CallGraph callGraph,
            HiFunction lca,
            Map<String, List<CandidateApi>> methodToApis
    ) {
        List<CandidateApi> reachableApis = new ArrayList<>();

        for (Map.Entry<String, List<CandidateApi>> entry : methodToApis.entrySet()) {
            String methodSig = entry.getKey();
            List<CandidateApi> apis = entry.getValue();

            HiFunction target = resolveFunction(callGraph, methodSig);
            if (target == null) {
                continue;
            }

            // BFS check if reachable from LCA to target
            if (isReachable(callGraph, lca, target)) {
                reachableApis.addAll(apis);
            }
        }

        return deduplicateApis(reachableApis);
    }

    /**
     * BFS check if reachable from source to target.
     */
    private static boolean isReachable(CallGraph callGraph, HiFunction source, HiFunction target) {
        if (source == null || target == null) {
            return false;
        }

        if (source == target) {
            return true;
        }

        Set<HiFunction> visited = new HashSet<>();
        Deque<HiFunction> queue = new ArrayDeque<>();
        queue.add(source);
        visited.add(source);

        while (!queue.isEmpty()) {
            HiFunction current = queue.poll();

            for (HiFunction callee : callGraph.getCalleesByCaller(current)) {
                if (callee == null) {
                    continue;
                }

                if (callee == target) {
                    return true;
                }

                if (!visited.contains(callee)) {
                    visited.add(callee);
                    queue.add(callee);
                }
            }
        }

        return false;
    }

    /**
     * Parse function object from function signature.
     */
    private static HiFunction resolveFunction(CallGraph callGraph, String methodSig) {
        if (callGraph == null || isBlank(methodSig)) {
            return null;
        }

        // Simple match: compare simplified function names
        String simpleName = simplifyMethodName(methodSig);

        for (HiFunction func : visitedFunctions(callGraph)) {
            String funcSig = safeFunctionSig(func);
            if (funcSig != null && simplifyMethodName(funcSig).equals(simpleName)) {
                return func;
            }
        }

        return null;
    }

    /**
     * Get all functions in CallGraph.
     */
    private static Set<HiFunction> visitedFunctions(CallGraph callGraph) {
        Set<HiFunction> funcs = new HashSet<>();

        for (HiFunction entry : callGraph.getEntryFunctions()) {
            funcs.add(entry);
        }

        for (HiFunction func : funcs) {
            funcs.addAll(callGraph.getCalleesByCaller(func));
        }

        return funcs;
    }

    /**
     * Get function signature.
     */
    private static String safeFunctionSig(HiFunction func) {
        if (func == null) {
            return null;
        }
        try {
            return func.getSignature().toString();
        } catch (Throwable t) {
            try {
                return func.getName();
            } catch (Throwable t2) {
                return null;
            }
        }
    }

    /**
     * Fallback: LCA detection based on call chain paths.
     */
    private static List<UnifiedPrivacyReport.MultiSourceCollaboration> analyzeLcaByPath(
            UnifiedPrivacyReport report,
            ProfileCombinationRule rule,
            Map<String, List<CandidateApi>> matchedMethodToApis,
            Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex
    ) {
        List<UnifiedPrivacyReport.MultiSourceCollaboration> results = new ArrayList<>();

        Map<Integer, UnifiedPrivacyReport.CallChainReport> fullChainByApiIndex = buildCallChainIndex(report);
        List<CandidateApi> allCandidates = collectAllArkTsCandidates(report);
        List<CandidatePath> candidatePaths = buildCandidatePaths(allCandidates, fullChainByApiIndex);

        if (candidatePaths.isEmpty()) {
            return results;
        }

        Map<Integer, CandidatePath> pathByApiIndex = new LinkedHashMap<>();
        for (CandidatePath cp : candidatePaths) {
            pathByApiIndex.put(cp.candidate.apiUsageIndex, cp);
        }

        // Collect all hit APIs together
        List<CandidateApi> allMatched = new ArrayList<>();
        for (List<CandidateApi> apis : matchedMethodToApis.values()) {
            allMatched.addAll(apis);
        }

        // Use path matching to find LCA
        Map<String, List<CandidateApi>> lcaToCandidates = new LinkedHashMap<>();
        for (CandidatePath candidatePath : candidatePaths) {
            for (String ancestor : candidatePath.path) {
                if (isBlank(ancestor) || "unknown".equals(ancestor)) {
                    continue;
                }
                lcaToCandidates
                        .computeIfAbsent(ancestor, k -> new ArrayList<>())
                        .add(candidatePath.candidate);
            }
        }

        Map<String, LcaMatch> bestMatchByApiSet = new LinkedHashMap<>();

        for (Map.Entry<String, List<CandidateApi>> entry : lcaToCandidates.entrySet()) {
            String lcaMethod = entry.getKey();
            List<CandidateApi> coveredCandidates = deduplicateApis(entry.getValue());
            List<CandidateApi> matchedApis = matchRuleInMethod(rule, coveredCandidates);

            if (matchedApis.size() < 2) {
                continue;
            }

            if (allSameDeclaringMethod(matchedApis)) {
                continue;
            }

            String apiSetKey = buildApiSetKey(matchedApis);
            int depthScore = computeLcaDepthScore(lcaMethod, matchedApis, pathByApiIndex);

            LcaMatch old = bestMatchByApiSet.get(apiSetKey);
            if (old == null || depthScore > old.depthScore) {
                LcaMatch match = new LcaMatch();
                match.rule = rule;
                match.lcaMethod = lcaMethod;
                match.matchedApis = matchedApis;
                match.depthScore = depthScore;
                bestMatchByApiSet.put(apiSetKey, match);
            }
        }

        for (LcaMatch match : bestMatchByApiSet.values()) {
            UnifiedPrivacyReport.MultiSourceCollaboration collab =
                    buildLcaCollaboration(
                            match.rule,
                            match.lcaMethod,
                            match.matchedApis,
                            fullChainByApiIndex
                    );
            results.add(collab);
        }

        return results;
    }

    // ======================================================
    // 1.2 same-file Rule Matching
    // ======================================================

    private static List<UnifiedPrivacyReport.MultiSourceCollaboration> analyzeSameFileByRules(
            UnifiedPrivacyReport report,
            List<ProfileCombinationRule> rules
    ) {
        List<UnifiedPrivacyReport.MultiSourceCollaboration> results = new ArrayList<>();

        Map<String, List<CandidateApi>> fileToApis = collectArkTsApisByFile(report);
        Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex = buildCallChainIndex(report);

        Set<String> emittedKeys = new LinkedHashSet<>();

        for (Map.Entry<String, List<CandidateApi>> entry : fileToApis.entrySet()) {
            String file = entry.getKey();
            List<CandidateApi> fileApis = deduplicateApis(entry.getValue());

            for (ProfileCombinationRule rule : rules) {
                if (!isSameFileRule(rule)) {
                    continue;
                }

                /*
                 * Reuse the original rule matching logic.
                 * matchRuleInMethod(...) actually only checks if an API set satisfies requiredApis,
                 * does not depend on "method" semantics, so same_file can reuse it.
                 */
                List<CandidateApi> matchedApis = matchRuleInMethod(rule, fileApis);

                if (matchedApis.size() < 2) {
                    continue;
                }

                String emitKey = safe(rule.ruleId) + "|" + file;
                if (emittedKeys.contains(emitKey)) {
                    continue;
                }
                emittedKeys.add(emitKey);

                UnifiedPrivacyReport.MultiSourceCollaboration collab =
                        buildSameFileCollaboration(
                                rule,
                                file,
                                matchedApis,
                                chainByApiIndex
                        );

                results.add(collab);
            }
        }

        return results;
    }

    private static Map<String, List<CandidateApi>> collectArkTsApisByMethod(
            UnifiedPrivacyReport report
    ) {
        Map<String, List<CandidateApi>> methodToApis = new LinkedHashMap<>();

        for (int i = 0; i < report.privacyApiUsages.size(); i++) {
            UnifiedPrivacyReport.ApiUsage usage = report.privacyApiUsages.get(i);

            if (!isValidArkTsUsage(usage)) {
                continue;
            }

            CandidateApi candidate = new CandidateApi();
            candidate.apiUsageIndex = i;
            candidate.usage = usage;
            candidate.category = normalizeCategory(usage);
            candidate.declaringMethod = usage.declaringMethod;

            methodToApis
                    .computeIfAbsent(usage.declaringMethod, k -> new ArrayList<>())
                    .add(candidate);
        }

        return methodToApis;
    }

    private static Map<String, List<CandidateApi>> collectArkTsApisByFile(
            UnifiedPrivacyReport report
    ) {
        Map<String, List<CandidateApi>> fileToApis = new LinkedHashMap<>();

        for (int i = 0; i < report.privacyApiUsages.size(); i++) {
            UnifiedPrivacyReport.ApiUsage usage = report.privacyApiUsages.get(i);

            if (!isValidArkTsUsage(usage)) {
                continue;
            }

            if (isBlank(usage.file)) {
                continue;
            }

            CandidateApi candidate = new CandidateApi();
            candidate.apiUsageIndex = i;
            candidate.usage = usage;
            candidate.category = normalizeCategory(usage);
            candidate.declaringMethod = usage.declaringMethod;

            fileToApis
                    .computeIfAbsent(usage.file, k -> new ArrayList<>())
                    .add(candidate);
        }

        return fileToApis;
    }

    private static List<CandidateApi> collectAllArkTsCandidates(
            UnifiedPrivacyReport report
    ) {
        List<CandidateApi> result = new ArrayList<>();

        if (report == null || report.privacyApiUsages == null) {
            return result;
        }

        for (int i = 0; i < report.privacyApiUsages.size(); i++) {
            UnifiedPrivacyReport.ApiUsage usage = report.privacyApiUsages.get(i);

            if (!isValidArkTsUsage(usage)) {
                continue;
            }

            CandidateApi candidate = new CandidateApi();
            candidate.apiUsageIndex = i;
            candidate.usage = usage;
            candidate.category = normalizeCategory(usage);
            candidate.declaringMethod = usage.declaringMethod;

            result.add(candidate);
        }

        return deduplicateApis(result);
    }


    private static List<CandidatePath> buildCandidatePaths(
            List<CandidateApi> candidates,
            Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex
    ) {
        List<CandidatePath> result = new ArrayList<>();

        if (candidates == null || candidates.isEmpty()) {
            return result;
        }

        for (CandidateApi candidate : candidates) {
            UnifiedPrivacyReport.CallChainReport chain =
                    chainByApiIndex.get(candidate.apiUsageIndex);

            if (chain == null) {
                continue;
            }

            List<String> path = buildMethodPath(chain, candidate);

            if (path.size() < 2) {
                continue;
            }

            CandidatePath candidatePath = new CandidatePath();
            candidatePath.candidate = candidate;
            candidatePath.chain = chain;
            candidatePath.path = path;

            result.add(candidatePath);
        }

        return result;
    }


    private static List<String> buildMethodPath(
            UnifiedPrivacyReport.CallChainReport chain,
            CandidateApi candidate
    ) {
        List<String> path = new ArrayList<>();

        if (chain == null) {
            return path;
        }

        if (chain.entryMethod != null && !isBlank(chain.entryMethod.name)) {
            path.add(simplifyMethodName(chain.entryMethod.name));
        }

        if (chain.chain != null) {
            for (UnifiedPrivacyReport.CallEdge edge : chain.chain) {
                if (edge == null) {
                    continue;
                }

                String callee = prefer(edge.resolvedCalleeName, edge.callee);
                if (!isBlank(callee)) {
                    path.add(simplifyMethodName(callee));
                }
            }
        }

        if (candidate != null && !isBlank(candidate.declaringMethod)) {
            String sourceMethod = simplifyMethodName(candidate.declaringMethod);

            if (path.isEmpty() || !path.get(path.size() - 1).equals(sourceMethod)) {
                path.add(sourceMethod);
            }
        }

        return deduplicateConsecutive(path);
    }


    private static List<String> deduplicateConsecutive(List<String> input) {
        List<String> result = new ArrayList<>();

        if (input == null || input.isEmpty()) {
            return result;
        }

        String last = null;

        for (String item : input) {
            if (isBlank(item)) {
                continue;
            }

            if (!item.equals(last)) {
                result.add(item);
                last = item;
            }
        }

        return result;
    }

    private static List<CandidateApi> matchRuleInMethod(
            ProfileCombinationRule rule,
            List<CandidateApi> methodApis
    ) {
        Map<String, CandidateApi> matched = new LinkedHashMap<>();

        if (rule == null || rule.requiredApis == null || rule.requiredApis.isEmpty()) {
            return new ArrayList<>();
        }

        for (ApiRequirement requirement : rule.requiredApis) {
            List<CandidateApi> requirementMatches = new ArrayList<>();

            for (CandidateApi candidate : methodApis) {
                if (matchesRequirement(candidate, requirement)) {
                    requirementMatches.add(candidate);
                }
            }

            /*
             * If any requiredApi condition is not satisfied, this rule does not hit.
             */
            if (requirementMatches.isEmpty()) {
                return new ArrayList<>();
            }

            /*
             * Keep all APIs matching this requirement in the report.
             * For example, if requirement is category=device_identity.hardware,
             * then brand/productModel/deviceType will all enter this collaboration group.
             */
            for (CandidateApi candidate : requirementMatches) {
                matched.put(buildCandidateKey(candidate), candidate);
            }
        }

        return new ArrayList<>(matched.values());
    }

    private static boolean matchesRequirement(
            CandidateApi candidate,
            ApiRequirement requirement
    ) {
        if (candidate == null || candidate.usage == null || requirement == null) {
            return false;
        }

        boolean hasAnyCondition = false;

        if (!isBlank(requirement.api)) {
            hasAnyCondition = true;
            String actualApi = buildApiName(candidate.usage);
            if (!matchesText(actualApi, requirement.api)) {
                return false;
            }
        }

        if (!isBlank(requirement.category)) {
            hasAnyCondition = true;
            if (!matchesCategory(candidate.category, requirement.category)) {
                return false;
            }
        }

        if (!isBlank(requirement.namespace)) {
            hasAnyCondition = true;
            if (!matchesText(candidate.usage.namespace, requirement.namespace)) {
                return false;
            }
        }

        if (!isBlank(requirement.method)) {
            hasAnyCondition = true;
            if (!matchesText(candidate.usage.method, requirement.method)) {
                return false;
            }
        }

        return hasAnyCondition;
    }

    // ======================================================
    // 2. Collaboration Construction
    // ======================================================

    private static UnifiedPrivacyReport.MultiSourceCollaboration buildRuleMatchedCollaboration(
            ProfileCombinationRule rule,
            String declaringMethod,
            List<CandidateApi> matchedApis,
            Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex
    ) {
        UnifiedPrivacyReport.MultiSourceCollaboration collab =
                new UnifiedPrivacyReport.MultiSourceCollaboration();

        String lcaSimpleName = simplifyMethodName(declaringMethod);
        Set<String> categories = collectDistinctCategories(matchedApis);

        collab.ruleId = safeOr(rule.ruleId, "unknown_rule");
        collab.ruleName = safeOr(rule.ruleName, collab.ruleId);

        collab.detectionLevel = "same_method";
        collab.lcaMethod = lcaSimpleName;
        collab.lcaMethodSig = declaringMethod;
        collab.entryMethod = inferEntryMethodName(matchedApis, chainByApiIndex, lcaSimpleName);

        collab.categories = new ArrayList<>(categories);
        collab.apis = buildCollaborationApis(matchedApis);

        /*
         * Do not determine risk here.
         * If the team rule gives riskLevel, pass it through;
         * if not given, use unknown.
         */
        collab.riskLevel = safeOr(rule.riskLevel, "unknown");

        collab.confidence = "high";
        collab.reason = "Rule-match same_method: "
                + collab.ruleName
                + " requires "
                + rule.requiredApis.size()
                + " conditions; matched "
                + matchedApis.size()
                + " APIs.";

        collab.subgraph = buildSameMethodSubgraph(
                declaringMethod,
                lcaSimpleName,
                matchedApis,
                chainByApiIndex
        );

        return collab;
    }

    private static Set<String> collectDistinctDeclaringMethods(List<CandidateApi> candidates) {
        Set<String> methods = new TreeSet<>();

        if (candidates == null || candidates.isEmpty()) {
            return methods;
        }

        for (CandidateApi candidate : candidates) {
            if (candidate != null && !isBlank(candidate.declaringMethod)) {
                methods.add(simplifyMethodName(candidate.declaringMethod));
            }
        }

        return methods;
    }

    private static String simplifyFileName(String file) {
        if (isBlank(file)) {
            return "unknown";
        }

        String s = file.replace("\\", "/");

        int slash = s.lastIndexOf('/');
        if (slash >= 0 && slash + 1 < s.length()) {
            s = s.substring(slash + 1);
        }

        if (s.endsWith(".ets")) {
            s = s.substring(0, s.length() - ".ets".length());
        }

        if (s.endsWith(".abc")) {
            s = s.substring(0, s.length() - ".abc".length());
        }

        return s.isEmpty() ? "unknown" : s;
    }

    private static UnifiedPrivacyReport.MultiSourceCollaboration buildSameFileCollaboration(
            ProfileCombinationRule rule,
            String file,
            List<CandidateApi> matchedApis,
            Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex
    ) {
        UnifiedPrivacyReport.MultiSourceCollaboration collab =
                new UnifiedPrivacyReport.MultiSourceCollaboration();

        Set<String> categories = collectDistinctCategories(matchedApis);

        collab.ruleId = safeOr(rule.ruleId, "unknown_rule");
        collab.ruleName = safeOr(rule.ruleName, collab.ruleId);

        collab.detectionLevel = "same_file";

        /*
         * same_file does not have a strict LCA.
         * To keep the interface stable, lcaMethod uses a file-level virtual anchor.
         */
        collab.lcaMethod = "same_file:" + simplifyFileName(file);
        collab.lcaMethodSig = file;

        collab.entryMethod = inferEntryMethodName(
                matchedApis,
                chainByApiIndex,
                collab.lcaMethod
        );

        collab.categories = new ArrayList<>(categories);
        collab.apis = buildCollaborationApis(matchedApis);

        /*
         * Risk only passes through rules, does not determine in analyzer.
         */
        collab.riskLevel = safeOr(rule.riskLevel, "unknown");

        /*
         * same_file evidence is weaker than same_method, so confidence is set to medium.
         */
        collab.confidence = "medium";

        collab.reason = "Rule-match same_file: "
                + collab.ruleName
                + " requires "
                + rule.requiredApis.size()
                + " conditions; matched "
                + matchedApis.size()
                + " APIs in file "
                + file
                + ".";

        collab.subgraph = buildSameFileSubgraph(
                file,
                matchedApis,
                chainByApiIndex
        );

        return collab;
    }

    private static UnifiedPrivacyReport.MultiSourceCollaboration buildLcaCollaboration(
            ProfileCombinationRule rule,
            String lcaMethod,
            List<CandidateApi> matchedApis,
            Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex
    ) {
        UnifiedPrivacyReport.MultiSourceCollaboration collab =
                new UnifiedPrivacyReport.MultiSourceCollaboration();

        Set<String> categories = collectDistinctCategories(matchedApis);

        collab.ruleId = safeOr(rule.ruleId, "unknown_rule");
        collab.ruleName = safeOr(rule.ruleName, collab.ruleId);

        collab.detectionLevel = "lca";
        collab.lcaMethod = lcaMethod;
        collab.lcaMethodSig = lcaMethod;

        collab.entryMethod = inferEntryMethodName(
                matchedApis,
                chainByApiIndex,
                lcaMethod
        );

        collab.categories = new ArrayList<>(categories);
        collab.apis = buildCollaborationApis(matchedApis);

        /*
         * Risk only passes through rules, does not determine in analyzer.
         */
        collab.riskLevel = safeOr(rule.riskLevel, "unknown");

        /*
         * LCA evidence is stronger than same_file, but weaker than same_method.
         */
        collab.confidence = "high";

        collab.reason = "Rule-match lca: "
                + collab.ruleName
                + " requires "
                + rule.requiredApis.size()
                + " conditions; matched "
                + matchedApis.size()
                + " APIs under common ancestor "
                + lcaMethod
                + ".";

        collab.subgraph = buildLcaSubgraph(
                lcaMethod,
                matchedApis,
                chainByApiIndex
        );

        return collab;
    }

    /**
     * Build collaboration detection result based on CallGraph LCA.
     * Similar to buildLcaCollaboration, but uses HiFunction objects instead of strings.
     */
    private static UnifiedPrivacyReport.MultiSourceCollaboration buildCgLcaCollaboration(
            ProfileCombinationRule rule,
            HiFunction lca,
            String lcaSig,
            List<CandidateApi> matchedApis,
            Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex
    ) {
        UnifiedPrivacyReport.MultiSourceCollaboration collab =
                new UnifiedPrivacyReport.MultiSourceCollaboration();

        Set<String> categories = collectDistinctCategories(matchedApis);

        collab.ruleId = safeOr(rule.ruleId, "unknown_rule");
        collab.ruleName = safeOr(rule.ruleName, collab.ruleId);

        collab.detectionLevel = "lca_cg";
        collab.lcaMethod = lca != null ? safeFunctionSig(lca) : lcaSig;
        collab.lcaMethodSig = lcaSig;

        collab.entryMethod = inferEntryMethodName(
                matchedApis,
                chainByApiIndex,
                collab.lcaMethod
        );

        collab.categories = new ArrayList<>(categories);
        collab.apis = buildCollaborationApis(matchedApis);

        collab.riskLevel = safeOr(rule.riskLevel, "unknown");

        collab.confidence = "high";

        collab.reason = "CallGraph-based LCA: "
                + collab.ruleName
                + " requires "
                + rule.requiredApis.size()
                + " conditions; matched "
                + matchedApis.size()
                + " APIs under verified CallGraph ancestor "
                + collab.lcaMethod
                + ".";

        collab.subgraph = buildCgLcaSubgraph(
                lcaSig,
                matchedApis,
                chainByApiIndex
        );

        return collab;
    }

    private static UnifiedPrivacyReport.CollaborationSubgraph buildCgLcaSubgraph(
            String lcaMethod,
            List<CandidateApi> candidates,
            Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex
    ) {
        UnifiedPrivacyReport.CollaborationSubgraph subgraph =
                new UnifiedPrivacyReport.CollaborationSubgraph();

        UnifiedPrivacyReport.CallChainReport representativeChain =
                findRepresentativeChain(candidates, chainByApiIndex);

        if (representativeChain != null) {
            subgraph.entry = copyEntryMethod(representativeChain.entryMethod);
            subgraph.entryToLca = extractEntryToLca(representativeChain, lcaMethod);
        } else {
            subgraph.entry = new UnifiedPrivacyReport.EntryMethod();
            subgraph.entry.name = lcaMethod;
            subgraph.entry.type = "method";
            subgraph.entry.file = inferFile(candidates);
            subgraph.entry.line = -1;

            subgraph.entryToLca = new ArrayList<>();
        }

        subgraph.lcaMethodSig = lcaMethod;

        for (CandidateApi candidate : candidates) {
            UnifiedPrivacyReport.CollaborationBranch branch =
                    new UnifiedPrivacyReport.CollaborationBranch();

            branch.apiUsageIndex = candidate.apiUsageIndex;
            branch.api = buildApiName(candidate.usage);
            branch.category = candidate.category;
            branch.declaringMethod = candidate.declaringMethod;

            UnifiedPrivacyReport.CallChainReport chain =
                    chainByApiIndex.get(candidate.apiUsageIndex);

            if (chain != null) {
                branch.lcaToSource = extractLcaToSource(chain, lcaMethod);
            } else {
                branch.lcaToSource = new ArrayList<>();
            }

            if (chain != null && chain.dataSinks != null) {
                branch.sinks = new ArrayList<>(chain.dataSinks);
            } else {
                branch.sinks = new ArrayList<>();
            }

            subgraph.branches.add(branch);
        }

        subgraph.semanticContext = buildLcaSemanticContext(
                lcaMethod,
                candidates
        );

        return subgraph;
    }

    private static UnifiedPrivacyReport.CollaborationSubgraph buildSameMethodSubgraph(
            String declaringMethod,
            String lcaSimpleName,
            List<CandidateApi> candidates,
            Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex
    ) {
        UnifiedPrivacyReport.CollaborationSubgraph subgraph =
                new UnifiedPrivacyReport.CollaborationSubgraph();

        UnifiedPrivacyReport.CallChainReport representativeChain =
                findRepresentativeChain(candidates, chainByApiIndex);

        if (representativeChain != null) {
            subgraph.entry = copyEntryMethod(representativeChain.entryMethod);
            subgraph.entryToLca = extractEntryToLca(representativeChain, lcaSimpleName);
            subgraph.semanticContext = buildCollaborationSemanticContext(
                    representativeChain,
                    lcaSimpleName,
                    candidates
            );
        } else {
            subgraph.entry = new UnifiedPrivacyReport.EntryMethod();
            subgraph.entry.name = lcaSimpleName;
            subgraph.entry.type = "method";
            subgraph.entry.file = inferFile(candidates);
            subgraph.entry.line = -1;

            subgraph.semanticContext = buildFallbackSemanticContext(
                    lcaSimpleName,
                    candidates
            );
        }

        subgraph.lcaMethodSig = declaringMethod;

        for (CandidateApi candidate : candidates) {
            UnifiedPrivacyReport.CollaborationBranch branch =
                    new UnifiedPrivacyReport.CollaborationBranch();

            branch.apiUsageIndex = candidate.apiUsageIndex;
            branch.api = buildApiName(candidate.usage);
            branch.category = candidate.category;
            branch.declaringMethod = candidate.declaringMethod;

            /*
             * In same-method scenario, LCA is the source method.
             */
            branch.lcaToSource = new ArrayList<>();

            /*
             * IFDS is currently disabled, so usually empty.
             * If IFDS is restored in the future, sinks from callChain will be inherited here.
             */
            UnifiedPrivacyReport.CallChainReport chain =
                    chainByApiIndex.get(candidate.apiUsageIndex);

            if (chain != null && chain.dataSinks != null) {
                branch.sinks = new ArrayList<>(chain.dataSinks);
            } else {
                branch.sinks = new ArrayList<>();
            }

            subgraph.branches.add(branch);
        }

        return subgraph;
    }

    private static UnifiedPrivacyReport.CollaborationSubgraph buildSameFileSubgraph(
            String file,
            List<CandidateApi> candidates,
            Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex
    ) {
        UnifiedPrivacyReport.CollaborationSubgraph subgraph =
                new UnifiedPrivacyReport.CollaborationSubgraph();

        UnifiedPrivacyReport.CallChainReport representativeChain =
                findRepresentativeChain(candidates, chainByApiIndex);

        if (representativeChain != null) {
            subgraph.entry = copyEntryMethod(representativeChain.entryMethod);
        } else {
            subgraph.entry = new UnifiedPrivacyReport.EntryMethod();
            subgraph.entry.name = "same_file:" + simplifyFileName(file);
            subgraph.entry.type = "file";
            subgraph.entry.file = file;
            subgraph.entry.line = -1;
        }

        /*
         * same_file has no real LCA.
         */
        subgraph.entryToLca = new ArrayList<>();
        subgraph.lcaMethodSig = file;

        for (CandidateApi candidate : candidates) {
            UnifiedPrivacyReport.CollaborationBranch branch =
                    new UnifiedPrivacyReport.CollaborationBranch();

            branch.apiUsageIndex = candidate.apiUsageIndex;
            branch.api = buildApiName(candidate.usage);
            branch.category = candidate.category;
            branch.declaringMethod = candidate.declaringMethod;

            /*
             * There is no strict path from LCA to source in same_file mode.
             * Here we keep this API's own call chain as approximate evidence path.
             */
            UnifiedPrivacyReport.CallChainReport chain =
                    chainByApiIndex.get(candidate.apiUsageIndex);

            if (chain != null && chain.chain != null) {
                branch.lcaToSource = copyChainEdges(chain.chain);
            } else {
                branch.lcaToSource = new ArrayList<>();
            }

            if (chain != null && chain.dataSinks != null) {
                branch.sinks = new ArrayList<>(chain.dataSinks);
            } else {
                branch.sinks = new ArrayList<>();
            }

            subgraph.branches.add(branch);
        }

        subgraph.semanticContext = buildSameFileSemanticContext(
                file,
                candidates
        );

        return subgraph;
    }

    private static UnifiedPrivacyReport.CollaborationSubgraph buildLcaSubgraph(
            String lcaMethod,
            List<CandidateApi> candidates,
            Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex
    ) {
        UnifiedPrivacyReport.CollaborationSubgraph subgraph =
                new UnifiedPrivacyReport.CollaborationSubgraph();

        UnifiedPrivacyReport.CallChainReport representativeChain =
                findRepresentativeChain(candidates, chainByApiIndex);

        if (representativeChain != null) {
            subgraph.entry = copyEntryMethod(representativeChain.entryMethod);
            subgraph.entryToLca = extractEntryToLca(representativeChain, lcaMethod);
        } else {
            subgraph.entry = new UnifiedPrivacyReport.EntryMethod();
            subgraph.entry.name = lcaMethod;
            subgraph.entry.type = "method";
            subgraph.entry.file = inferFile(candidates);
            subgraph.entry.line = -1;

            subgraph.entryToLca = new ArrayList<>();
        }

        subgraph.lcaMethodSig = lcaMethod;

        for (CandidateApi candidate : candidates) {
            UnifiedPrivacyReport.CollaborationBranch branch =
                    new UnifiedPrivacyReport.CollaborationBranch();

            branch.apiUsageIndex = candidate.apiUsageIndex;
            branch.api = buildApiName(candidate.usage);
            branch.category = candidate.category;
            branch.declaringMethod = candidate.declaringMethod;

            UnifiedPrivacyReport.CallChainReport chain =
                    chainByApiIndex.get(candidate.apiUsageIndex);

            if (chain != null) {
                branch.lcaToSource = extractLcaToSource(chain, lcaMethod);
            } else {
                branch.lcaToSource = new ArrayList<>();
            }

            if (chain != null && chain.dataSinks != null) {
                branch.sinks = new ArrayList<>(chain.dataSinks);
            } else {
                branch.sinks = new ArrayList<>();
            }

            subgraph.branches.add(branch);
        }

        subgraph.semanticContext = buildLcaSemanticContext(
                lcaMethod,
                candidates
        );

        return subgraph;
    }

    // ======================================================
    // 3. Rule loading
    // ======================================================

    private static List<ProfileCombinationRule> loadRules(File ruleFile) {
        if (ruleFile == null || !ruleFile.exists()) {
            Logger.log("[MultiSource] rule file not found: "
                    + (ruleFile == null ? "null" : ruleFile.getAbsolutePath()));
            return new ArrayList<>();
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

            List<ProfileCombinationRule> rules = mapper.readValue(
                    ruleFile,
                    new TypeReference<List<ProfileCombinationRule>>() {}
            );

            if (rules == null) {
                return new ArrayList<>();
            }

            return rules;

        } catch (IOException e) {
            Logger.error("[MultiSource] failed to load rule file: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static class ProfileCombinationRule {
        public String ruleId;
        public String ruleName;

        /**
         * Currently only supports same_method.
         */
        public String matchScope;

        /**
         * Optional. We only pass through, do not calculate.
         */
        public String riskLevel;

        public List<ApiRequirement> requiredApis = new ArrayList<>();
    }

    public static class ApiRequirement {
        /**
         * Full API can be written:
         * deviceInfo.productModel
         */
        public String api;

        /**
         * Profiling category can be written:
         * device_identity.hardware
         * device_identity.*
         */
        public String category;

        public String namespace;
        public String method;
    }

    // ======================================================
    // 4. Basic Filtering and Normalization
    // ======================================================

    private static boolean isSameMethodRule(ProfileCombinationRule rule) {
        if (rule == null) {
            return false;
        }

        if (isBlank(rule.matchScope)) {
            return true;
        }

        return DEFAULT_SCOPE.equalsIgnoreCase(rule.matchScope.trim());
    }

    private static boolean isLcaRule(ProfileCombinationRule rule) {
        if (rule == null || isBlank(rule.matchScope)) {
            return false;
        }

        return "lca".equalsIgnoreCase(rule.matchScope.trim());
    }

    private static boolean isSameFileRule(ProfileCombinationRule rule) {
        if (rule == null || isBlank(rule.matchScope)) {
            return false;
        }

        return "same_file".equalsIgnoreCase(rule.matchScope.trim());
    }

    private static boolean isValidArkTsUsage(UnifiedPrivacyReport.ApiUsage usage) {
        if (usage == null) {
            return false;
        }

        if (!"ArkTS".equals(usage.sourceLayer)) {
            return false;
        }

        if (isBlank(usage.declaringMethod)) {
            return false;
        }

        if (isBlank(usage.method) && isBlank(usage.namespace) && isBlank(usage.profilingCategory)) {
            return false;
        }

        return true;
    }

    private static String normalizeCategory(UnifiedPrivacyReport.ApiUsage usage) {
        if (usage == null) {
            return "unknown";
        }

        if (!isBlank(usage.profilingCategory)) {
            return usage.profilingCategory.trim();
        }

        if (!isBlank(usage.category)) {
            return usage.category.trim();
        }

        return "unknown";
    }

    private static List<CandidateApi> deduplicateApis(List<CandidateApi> input) {
        Map<String, CandidateApi> map = new LinkedHashMap<>();

        for (CandidateApi candidate : input) {
            map.putIfAbsent(buildCandidateKey(candidate), candidate);
        }

        return new ArrayList<>(map.values());
    }

    private static String buildCandidateKey(CandidateApi candidate) {
        if (candidate == null || candidate.usage == null) {
            return "null";
        }

        UnifiedPrivacyReport.ApiUsage usage = candidate.usage;

        return safe(usage.namespace)
                + "|"
                + safe(usage.method)
                + "|"
                + safe(candidate.category)
                + "|"
                + safe(usage.declaringMethod);
    }

    private static Set<String> collectDistinctCategories(List<CandidateApi> candidates) {
        Set<String> categories = new TreeSet<>();

        for (CandidateApi candidate : candidates) {
            if (!isBlank(candidate.category) && !"unknown".equals(candidate.category)) {
                categories.add(candidate.category);
            }
        }

        return categories;
    }

    // ======================================================
    // 5. Chain / Subgraph Related
    // ======================================================

    private static Map<Integer, UnifiedPrivacyReport.CallChainReport> buildCallChainIndex(
            UnifiedPrivacyReport report
    ) {
        Map<Integer, UnifiedPrivacyReport.CallChainReport> map = new LinkedHashMap<>();

        if (report.callChains == null) {
            return map;
        }

        for (UnifiedPrivacyReport.CallChainReport chain : report.callChains) {
            if (chain == null) {
                continue;
            }

            map.putIfAbsent(chain.apiUsageIndex, chain);
        }

        return map;
    }

    private static UnifiedPrivacyReport.CallChainReport findRepresentativeChain(
            List<CandidateApi> candidates,
            Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex
    ) {
        for (CandidateApi candidate : candidates) {
            UnifiedPrivacyReport.CallChainReport chain =
                    chainByApiIndex.get(candidate.apiUsageIndex);

            if (chain != null) {
                return chain;
            }
        }

        return null;
    }

    private static List<UnifiedPrivacyReport.CallEdge> extractEntryToLca(
            UnifiedPrivacyReport.CallChainReport chain,
            String lcaSimpleName
    ) {
        List<UnifiedPrivacyReport.CallEdge> result = new ArrayList<>();

        if (chain == null || chain.chain == null || chain.chain.isEmpty()) {
            return result;
        }

        for (UnifiedPrivacyReport.CallEdge edge : chain.chain) {
            UnifiedPrivacyReport.CallEdge copied = copyCallEdge(edge);
            result.add(copied);

            if (methodNameMatches(edge.callee, lcaSimpleName)
                    || methodNameMatches(edge.resolvedCalleeName, lcaSimpleName)) {
                break;
            }
        }

        return result;
    }

    private static List<UnifiedPrivacyReport.CallEdge> extractLcaToSource(
            UnifiedPrivacyReport.CallChainReport chain,
            String lcaMethod
    ) {
        List<UnifiedPrivacyReport.CallEdge> result = new ArrayList<>();

        if (chain == null || chain.chain == null || chain.chain.isEmpty()) {
            return result;
        }

        boolean seenLca = false;

        if (chain.entryMethod != null
                && methodNameMatches(chain.entryMethod.name, lcaMethod)) {
            seenLca = true;
        }

        for (UnifiedPrivacyReport.CallEdge edge : chain.chain) {
            if (edge == null) {
                continue;
            }

            String caller = prefer(edge.resolvedCallerName, edge.caller);
            String callee = prefer(edge.resolvedCalleeName, edge.callee);

            if (!seenLca && methodNameMatches(caller, lcaMethod)) {
                seenLca = true;
            }

            if (seenLca) {
                result.add(copyCallEdge(edge));
                continue;
            }

            /*
             * When the current edge's callee is LCA, this edge belongs to entry -> LCA,
             * not LCA -> source, so do not add to result.
             */
            if (methodNameMatches(callee, lcaMethod)) {
                seenLca = true;
            }
        }

        return result;
    }

    private static UnifiedPrivacyReport.EntryMethod copyEntryMethod(
            UnifiedPrivacyReport.EntryMethod original
    ) {
        if (original == null) {
            return null;
        }

        UnifiedPrivacyReport.EntryMethod copied = new UnifiedPrivacyReport.EntryMethod();
        copied.name = original.name;
        copied.type = original.type;
        copied.file = original.file;
        copied.line = original.line;
        return copied;
    }

    private static UnifiedPrivacyReport.CallEdge copyCallEdge(
            UnifiedPrivacyReport.CallEdge original
    ) {
        UnifiedPrivacyReport.CallEdge copied = new UnifiedPrivacyReport.CallEdge();

        if (original == null) {
            return copied;
        }

        copied.caller = original.caller;
        copied.callee = original.callee;
        copied.callType = original.callType;
        copied.resolvedCallerName = original.resolvedCallerName;
        copied.resolvedCalleeName = original.resolvedCalleeName;

        return copied;
    }

    private static List<UnifiedPrivacyReport.CallEdge> copyChainEdges(
            List<UnifiedPrivacyReport.CallEdge> edges
    ) {
        List<UnifiedPrivacyReport.CallEdge> copied = new ArrayList<>();

        if (edges == null || edges.isEmpty()) {
            return copied;
        }

        for (UnifiedPrivacyReport.CallEdge edge : edges) {
            copied.add(copyCallEdge(edge));
        }

        return copied;
    }

    // ======================================================
    // 6. semantic context
    // ======================================================

    private static UnifiedPrivacyReport.SemanticContext buildCollaborationSemanticContext(
            UnifiedPrivacyReport.CallChainReport representativeChain,
            String lcaSimpleName,
            List<CandidateApi> candidates
    ) {
        UnifiedPrivacyReport.SemanticContext context =
                new UnifiedPrivacyReport.SemanticContext();

        if (representativeChain.semanticContext != null) {
            context.pageName = representativeChain.semanticContext.pageName;
            context.componentClass = representativeChain.semanticContext.componentClass;
        } else if (representativeChain.entryMethod != null) {
            context.pageName = representativeChain.entryMethod.file;
            context.componentClass = "UnknownClass";
        } else {
            context.pageName = inferFile(candidates);
            context.componentClass = "UnknownClass";
        }

        context.semanticAnchor = lcaSimpleName;
        context.simplifiedChain = buildSimplifiedCollaborationChain(
                representativeChain,
                lcaSimpleName,
                candidates
        );

        context.purposeHint = "In "
                + safe(context.pageName)
                + ", function "
                + lcaSimpleName
                + "() matches profile-combination rule with APIs {"
                + buildApiListText(candidates)
                + "}";

        return context;
    }

    private static UnifiedPrivacyReport.SemanticContext buildFallbackSemanticContext(
            String lcaSimpleName,
            List<CandidateApi> candidates
    ) {
        UnifiedPrivacyReport.SemanticContext context =
                new UnifiedPrivacyReport.SemanticContext();

        context.pageName = inferFile(candidates);
        context.componentClass = "UnknownClass";
        context.semanticAnchor = lcaSimpleName;
        context.simplifiedChain = lcaSimpleName + "() -> {" + buildApiListText(candidates) + "}";
        context.purposeHint = "In "
                + safe(context.pageName)
                + ", function "
                + lcaSimpleName
                + "() matches profile-combination rule with APIs {"
                + buildApiListText(candidates)
                + "}";

        return context;
    }

    private static UnifiedPrivacyReport.SemanticContext buildSameFileSemanticContext(
            String file,
            List<CandidateApi> candidates
    ) {
        UnifiedPrivacyReport.SemanticContext context =
                new UnifiedPrivacyReport.SemanticContext();

        Set<String> categories = collectDistinctCategories(candidates);
        Set<String> methods = collectDistinctDeclaringMethods(candidates);

        context.pageName = simplifyFileName(file);
        context.componentClass = "UnknownClass";
        context.semanticAnchor = "same_file:" + simplifyFileName(file);

        context.simplifiedChain = "same_file:"
                + simplifyFileName(file)
                + " -> {"
                + buildApiListText(candidates)
                + "}";

        context.purposeHint = "In "
                + safe(file)
                + ", multiple methods jointly match a profile-combination rule with "
                + categories.size()
                + " categories ("
                + String.join(", ", categories)
                + ") and "
                + candidates.size()
                + " APIs across methods {"
                + String.join(", ", methods)
                + "}";

        return context;
    }

    private static UnifiedPrivacyReport.SemanticContext buildLcaSemanticContext(
            String lcaMethod,
            List<CandidateApi> candidates
    ) {
        UnifiedPrivacyReport.SemanticContext context =
                new UnifiedPrivacyReport.SemanticContext();

        Set<String> categories = collectDistinctCategories(candidates);
        Set<String> methods = collectDistinctDeclaringMethods(candidates);

        context.pageName = inferFile(candidates);
        context.componentClass = "UnknownClass";
        context.semanticAnchor = lcaMethod;

        context.simplifiedChain = lcaMethod
                + "() -> {"
                + buildApiListText(candidates)
                + "}";

        context.purposeHint = "Under common ancestor "
                + lcaMethod
                + "(), multiple methods jointly match a profile-combination rule with "
                + categories.size()
                + " categories ("
                + String.join(", ", categories)
                + ") and "
                + candidates.size()
                + " APIs across methods {"
                + String.join(", ", methods)
                + "}";

        return context;
    }

    private static String buildSimplifiedCollaborationChain(
            UnifiedPrivacyReport.CallChainReport chain,
            String lcaSimpleName,
            List<CandidateApi> candidates
    ) {
        String prefix;

        if (chain != null
                && chain.semanticContext != null
                && !isBlank(chain.semanticContext.simplifiedChain)) {
            String old = chain.semanticContext.simplifiedChain;
            int idx = old.indexOf(lcaSimpleName + "()");
            if (idx >= 0) {
                prefix = old.substring(0, idx + (lcaSimpleName + "()").length());
            } else {
                prefix = old;
            }
        } else {
            prefix = lcaSimpleName + "()";
        }

        return prefix + " -> {" + buildApiListText(candidates) + "}";
    }

    // ======================================================
    // 7. API Construction
    // ======================================================

    private static List<UnifiedPrivacyReport.CollaborationApi> buildCollaborationApis(
            List<CandidateApi> candidates
    ) {
        List<UnifiedPrivacyReport.CollaborationApi> apis = new ArrayList<>();

        for (CandidateApi candidate : candidates) {
            UnifiedPrivacyReport.ApiUsage usage = candidate.usage;

            UnifiedPrivacyReport.CollaborationApi api =
                    new UnifiedPrivacyReport.CollaborationApi();

            api.apiUsageIndex = candidate.apiUsageIndex;
            api.api = buildApiName(usage);
            api.category = candidate.category;
            api.namespace = usage.namespace;
            api.method = usage.method;
            api.declaringMethod = usage.declaringMethod;
            api.file = usage.file;

            apis.add(api);
        }

        return apis;
    }

    private static String buildApiName(UnifiedPrivacyReport.ApiUsage usage) {
        if (usage == null) {
            return "unknown";
        }

        if (!isBlank(usage.namespace) && !isBlank(usage.method)) {
            return usage.namespace + "." + usage.method;
        }

        if (!isBlank(usage.method)) {
            return usage.method;
        }

        return "unknown";
    }

    private static String buildApiListText(List<CandidateApi> candidates) {
        List<String> apiNames = new ArrayList<>();

        for (CandidateApi candidate : candidates) {
            apiNames.add(buildApiName(candidate.usage));
        }

        return String.join(", ", apiNames);
    }

    private static String inferEntryMethodName(
            List<CandidateApi> candidates,
            Map<Integer, UnifiedPrivacyReport.CallChainReport> chainByApiIndex,
            String fallback
    ) {
        UnifiedPrivacyReport.CallChainReport chain =
                findRepresentativeChain(candidates, chainByApiIndex);

        if (chain != null
                && chain.entryMethod != null
                && !isBlank(chain.entryMethod.name)) {
            return chain.entryMethod.name;
        }

        return fallback;
    }

    // ======================================================
    // 8. Text Matching
    // ======================================================

    private static boolean matchesText(String actual, String expected) {
        if (isBlank(actual) || isBlank(expected)) {
            return false;
        }

        return actual.trim().equals(expected.trim());
    }

    private static boolean matchesCategory(String actual, String expected) {
        if (isBlank(actual) || isBlank(expected)) {
            return false;
        }

        String a = actual.trim();
        String e = expected.trim();

        if (e.endsWith(".*")) {
            String prefix = e.substring(0, e.length() - 2);
            return a.equals(prefix) || a.startsWith(prefix + ".");
        }

        return a.equals(e);
    }

    // ======================================================
    // 9. String Utilities
    // ======================================================

    private static String simplifyMethodName(String methodSig) {
        if (methodSig == null) {
            return "unknown";
        }

        String s = methodSig.trim();

        int colon = s.lastIndexOf(':');
        if (colon >= 0 && colon + 1 < s.length()) {
            s = s.substring(colon + 1).trim();
        }

        int paren = s.indexOf('(');
        if (paren >= 0) {
            s = s.substring(0, paren).trim();
        }

        s = s.replace("[static]", "").trim();

        return s.isEmpty() ? "unknown" : s;
    }

    private static boolean methodNameMatches(String maybeMethod, String targetSimpleName) {
        if (isBlank(maybeMethod) || isBlank(targetSimpleName)) {
            return false;
        }

        String a = simplifyMethodName(maybeMethod);
        String b = simplifyMethodName(targetSimpleName);

        return a.equals(b) || a.endsWith("." + b) || b.endsWith("." + a);
    }

    private static String inferFile(List<CandidateApi> candidates) {
        if (candidates == null || candidates.isEmpty()) {
            return "unknown";
        }

        for (CandidateApi candidate : candidates) {
            if (candidate.usage != null && !isBlank(candidate.usage.file)) {
                return candidate.usage.file;
            }
        }

        return "unknown";
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }

    private static String safeOr(String value, String fallback) {
        return isBlank(value) ? fallback : value;
    }

    private static boolean allSameDeclaringMethod(List<CandidateApi> candidates) {
        if (candidates == null || candidates.isEmpty()) {
            return true;
        }

        String first = null;

        for (CandidateApi candidate : candidates) {
            if (candidate == null || isBlank(candidate.declaringMethod)) {
                continue;
            }

            String current = candidate.declaringMethod;

            if (first == null) {
                first = current;
            } else if (!first.equals(current)) {
                return false;
            }
        }

        return true;
    }


    private static String buildApiSetKey(List<CandidateApi> candidates) {
        List<String> keys = new ArrayList<>();

        if (candidates == null) {
            return "";
        }

        for (CandidateApi candidate : candidates) {
            if (candidate == null) {
                continue;
            }

            keys.add(String.valueOf(candidate.apiUsageIndex));
        }

        Collections.sort(keys);
        return String.join(",", keys);
    }


    private static int computeLcaDepthScore(
            String lcaMethod,
            List<CandidateApi> matchedApis,
            Map<Integer, CandidatePath> pathByApiIndex
    ) {
        if (isBlank(lcaMethod) || matchedApis == null || matchedApis.isEmpty()) {
            return -1;
        }

        int minDepth = Integer.MAX_VALUE;

        for (CandidateApi api : matchedApis) {
            CandidatePath path = pathByApiIndex.get(api.apiUsageIndex);

            if (path == null || path.path == null || path.path.isEmpty()) {
                return -1;
            }

            int depth = indexOfMethod(path.path, lcaMethod);

            if (depth < 0) {
                return -1;
            }

            minDepth = Math.min(minDepth, depth);
        }

        return minDepth == Integer.MAX_VALUE ? -1 : minDepth;
    }


    private static int indexOfMethod(List<String> path, String method) {
        if (path == null || path.isEmpty() || isBlank(method)) {
            return -1;
        }

        for (int i = 0; i < path.size(); i++) {
            if (methodNameMatches(path.get(i), method)) {
                return i;
            }
        }

        return -1;
    }


    private static String prefer(String first, String second) {
        if (!isBlank(first)) {
            return first;
        }

        if (!isBlank(second)) {
            return second;
        }

        return null;
    }

    // ======================================================
    // 10. Internal Candidate Model
    // ======================================================

    private static class CandidateApi {
        int apiUsageIndex;
        UnifiedPrivacyReport.ApiUsage usage;
        String category;
        String declaringMethod;
    }

    private static class CandidatePath {
        CandidateApi candidate;
        UnifiedPrivacyReport.CallChainReport chain;
        List<String> path = new ArrayList<>();
    }


    private static class LcaMatch {
        ProfileCombinationRule rule;
        String lcaMethod;
        List<CandidateApi> matchedApis = new ArrayList<>();
        int depthScore;
    }
}