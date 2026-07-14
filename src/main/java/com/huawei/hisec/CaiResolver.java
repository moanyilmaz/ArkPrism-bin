package com.huawei.hisec;

import com.huawei.hianalyzer.analysis.base.HiClass;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.base.HiFunction;
import com.huawei.hianalyzer.analysis.graph.callgraph.CallGraph;
import com.huawei.hianalyzer.analysis.graph.callgraph.pta.andersen.Andersen;
import com.huawei.hianalyzer.common.base.BaseClass;
import com.huawei.hianalyzer.common.type.InstanceType;
import com.huawei.hianalyzer.common.type.Type;
import com.huawei.hianalyzer.ir.stmt.CallStmt;
import com.huawei.hianalyzer.ir.stmt.Stmt;
import com.huawei.hianalyzer.ir.value.Local;

import java.util.*;
import java.util.stream.Collectors;

/**
 * CAIR: Conflict-Aware and Alias-Consistent API Identity Recovery.
 *
 * Replaces the per-call-site heuristic cascade in NamespaceResolver with:
 * 1. Evidence extraction with provenance (7 evidence kinds + weights)
 * 2. Alias component construction via Union-Find + comparePointers
 * 3. All-compatible candidate generation (not first-match)
 * 4. Joint constraint solving per alias component
 * 5. Ambiguity-aware abstention (entropy-based, replaces GENERIC_METHOD_BLACKLIST)
 * 6. Resolution certificate output (evidence trace + decision rationale)
 */
public class CaiResolver {

    // ======================================================
    // Configuration
    // ======================================================

    /** Enable CAIR algorithm. When false, falls back to old heuristic cascade. */
    public static boolean USE_CAIR = true;

    // ======================================================
    // Data Structures
    // ======================================================

    /** Evidence source kind with associated weight. */
    public enum EvidenceKind {
        PTA_CLASS(1.0),       // Andersen PTA points-to class
        STATIC_TYPE(0.8),     // Declared type from Local.getType()
        FACTORY_RETURN(0.7),  // Factory method return type via FunctionRef
        FACTORY_MAP(0.6),     // Hardcoded factory method → namespace map
        ROOT_QUALIFIER(0.5),  // Root qualifier from resolved name parsing
        PATH_TOKEN(0.4),      // Namespace token in path (e.g., "audio" in "audio.getAudioManager")
        VARIABLE_NAME(0.3);   // Variable name heuristic (e.g., audioManager → audio)

        public final double weight;
        EvidenceKind(double weight) { this.weight = weight; }
    }

    /** A single piece of namespace evidence with provenance. */
    public static class NamespaceEvidence {
        public final EvidenceKind kind;
        public final String namespace;   // The inferred namespace
        public final double weight;      // kind.weight (copied for convenience)
        public final String detail;      // Human-readable evidence description

        public NamespaceEvidence(EvidenceKind kind, String namespace, String detail) {
            this.kind = kind;
            this.namespace = namespace;
            this.weight = kind.weight;
            this.detail = detail;
        }

        @Override
        public String toString() {
            return kind + "(" + String.format("%.1f", weight) + "):" + namespace + " [" + detail + "]";
        }
    }

    /** Information about a single call site (indirect call). */
    public static class CallSiteInfo {
        public final Stmt stmt;
        public final Local receiver;         // May be null for static calls
        public final String methodName;      // Method being called (stripped of arguments)
        public final String resolvedFullName;// Full resolved API name from HiAnalyzer
        public final PreciseSensitiveApiScanner.ResolvedNameInfo nameInfo;
        public final List<NamespaceEvidence> evidence = new ArrayList<>();
        public final String fileName;
        public final String functionName;

        // Populated during alias component construction
        int aliasComponentId = -1;

        // Populated during candidate generation and constraint solving
        List<CandidateApi> allCandidates = new ArrayList<>();

        public CallSiteInfo(Stmt stmt, Local receiver, String methodName,
                           String resolvedFullName,
                           PreciseSensitiveApiScanner.ResolvedNameInfo nameInfo,
                           String fileName, String functionName) {
            this.stmt = stmt;
            this.receiver = receiver;
            this.methodName = methodName;
            this.resolvedFullName = resolvedFullName;
            this.nameInfo = nameInfo;
            this.fileName = fileName;
            this.functionName = functionName;
        }
    }

    /** Alias component: set of receiver variables that must share the same namespace. */
    public static class AliasComponent {
        public final int componentId;
        public final Set<Local> receiverVars = new LinkedHashSet<>();
        public final List<CallSiteInfo> callSites = new ArrayList<>();
        public Set<String> candidateNamespaces = new LinkedHashSet<>();

        public AliasComponent(int componentId) {
            this.componentId = componentId;
        }
    }

    /** A candidate API match for a call site. */
    public static class CandidateApi {
        public final String namespace;
        public final String methodName;
        public final PreciseSensitiveApiScanner.PrivacyApiRuleWithPkg rule;
        public double score;

        public CandidateApi(String namespace, String methodName,
                            PreciseSensitiveApiScanner.PrivacyApiRuleWithPkg rule, double score) {
            this.namespace = namespace;
            this.methodName = methodName;
            this.rule = rule;
            this.score = score;
        }
    }

    /** Resolution certificate: evidence trace and decision rationale. */
    public static class ResolutionCertificate {
        public List<NamespaceEvidence> contributingEvidence;
        public int aliasComponentId;
        public String decisionRationale;

        public ResolutionCertificate(List<NamespaceEvidence> contributingEvidence,
                                     int aliasComponentId, String decisionRationale) {
            this.contributingEvidence = contributingEvidence;
            this.aliasComponentId = aliasComponentId;
            this.decisionRationale = decisionRationale;
        }
    }

    /** Final resolution result for a call site. */
    public static class ResolutionResult {
        public final CallSiteInfo callSite;
        public CandidateApi bestCandidate;
        public boolean isAmbiguous;
        public double entropy;
        public ResolutionCertificate certificate;
        /** All candidates scored for this call site (before constraint solving). */
        public List<CandidateApi> allCandidates = new ArrayList<>();

        public ResolutionResult(CallSiteInfo callSite) {
            this.callSite = callSite;
        }
    }

    // ======================================================
    // Union-Find for Alias Component Construction
    // ======================================================

    private static class UnionFind {
        private final Map<Local, Local> parent = new LinkedHashMap<>();
        private final Map<Local, Integer> rank = new LinkedHashMap<>();

        Local find(Local x) {
            if (!parent.containsKey(x)) {
                parent.put(x, x);
                rank.put(x, 0);
                return x;
            }
            Local p = parent.get(x);
            if (p == x) return x;
            Local root = find(p);
            parent.put(x, root);
            return root;
        }

        void union(Local x, Local y) {
            Local rx = find(x);
            Local ry = find(y);
            if (rx == ry) return;
            int rxRank = rank.getOrDefault(rx, 0);
            int ryRank = rank.getOrDefault(ry, 0);
            if (rxRank < ryRank) {
                parent.put(rx, ry);
            } else if (rxRank > ryRank) {
                parent.put(ry, rx);
            } else {
                parent.put(ry, rx);
                rank.put(rx, rxRank + 1);
            }
        }
    }

    // ======================================================
    // Phase 1: Evidence Extraction with Provenance
    // ======================================================

    /**
     * Extracts namespace evidence from a call site using all 7 evidence kinds.
     * Each evidence carries its source kind, inferred namespace, weight, and a
     * human-readable detail string.
     */
    static void extractEvidence(CallSiteInfo site, Andersen andersen, CallGraph cg) {
        if (site.receiver != null) {
            // Evidence 1: PTA_CLASS — Andersen points-to analysis
            extractPtaClassEvidence(site, andersen);

            // Evidence 2: STATIC_TYPE — Declared type from Local.getType()
            extractStaticTypeEvidence(site);

            // Evidence 3 & 4: FACTORY_RETURN / FACTORY_MAP — Factory method resolution
            extractFactoryMethodEvidence(site, andersen, cg);

            // Evidence 7: VARIABLE_NAME — Variable name heuristic
            extractVariableNameEvidence(site);
        }

        // Evidence 5 & 6: ROOT_QUALIFIER / PATH_TOKEN — From resolved name
        extractPathBasedEvidence(site);
    }

    private static void extractPtaClassEvidence(CallSiteInfo site, Andersen andersen) {
        if (andersen == null) return;
        try {
            Set<HiClass> ptClasses = andersen.getPointsToHiClasses(site.receiver);
            if (ptClasses != null && !ptClasses.isEmpty()) {
                for (var cls : ptClasses) {
                    Set<String> nsCandidates = NamespaceResolver.extractNamespaceCandidatesFromClass(cls);
                    for (String ns : nsCandidates) {
                        site.evidence.add(new NamespaceEvidence(
                                EvidenceKind.PTA_CLASS, ns,
                                "points-to: " + cls.getName()));
                    }
                }
            }
        } catch (Throwable ignored) {}
    }

    private static void extractStaticTypeEvidence(CallSiteInfo site) {
        try {
            var type = site.receiver.getType();
            if (type == null) return;

            if (type instanceof InstanceType) {
                try {
                    var classRef = ((InstanceType) type).getClassRef();
                    if (classRef != null) {
                        BaseClass<?, ?> cls = classRef.resolve();
                        if (cls != null) {
                            Set<String> nsCandidates = NamespaceResolver.extractNamespaceCandidatesFromClass(cls);
                            for (String ns : nsCandidates) {
                                site.evidence.add(new NamespaceEvidence(
                                        EvidenceKind.STATIC_TYPE, ns,
                                        "declared-type: " + type.toString()));
                            }
                        }
                    }
                } catch (Throwable ignored) {}
            }

            // Fallback: use type's string representation
            String typeStr = type.toString();
            if (typeStr != null && !typeStr.isEmpty()) {
                int dot = typeStr.indexOf('.');
                String ns = dot > 0 ? typeStr.substring(0, dot) : typeStr;
                if (!ns.isEmpty() && !ns.equals("unknown") && !ns.equals("Object")) {
                    site.evidence.add(new NamespaceEvidence(
                            EvidenceKind.STATIC_TYPE, ns,
                            "type-string: " + typeStr));
                }
            }
        } catch (Throwable ignored) {}
    }

    private static void extractFactoryMethodEvidence(CallSiteInfo site, Andersen andersen, CallGraph cg) {
        try {
            List<Stmt> defStmts = NamespaceResolver.findDefinitionStmts(
                    site.receiver, site.stmt, andersen, cg);
            for (Stmt defStmt : defStmts) {
                if (defStmt instanceof CallStmt) {
                    CallStmt defCall = (CallStmt) defStmt;
                    try {
                        var callExpr = defCall.getCallExpr();
                        if (callExpr == null) continue;

                        // Strategy A: FunctionRef.getReturnType()
                        var funcRef = callExpr.getFunctionRef();
                        if (funcRef != null) {
                            var returnType = funcRef.getReturnType();
                            if (returnType != null) {
                                Set<String> nsCandidates =
                                        NamespaceResolver.extractNamespaceCandidatesFromReturnType(returnType);
                                for (String ns : nsCandidates) {
                                    site.evidence.add(new NamespaceEvidence(
                                            EvidenceKind.FACTORY_RETURN, ns,
                                            "factory-return: " + funcRef.getName()));
                                }
                            }
                        }

                        // Strategy B: FACTORY_METHOD_NAMESPACE_MAP lookup
                        String methodName = NamespaceResolver.extractMethodNameFromCallExpr(callExpr);
                        if (methodName != null && !methodName.isEmpty()) {
                            String lookupKey = methodName.toLowerCase(Locale.ROOT);
                            String mappedNs = NamespaceResolver.FACTORY_METHOD_NAMESPACE_MAP.get(lookupKey);
                            // Access the map via reflection or make it package-private
                            // For now, use a direct lookup approach
                            mappedNs = lookupFactoryMethodNamespaceMap(lookupKey);
                            if (mappedNs != null) {
                                site.evidence.add(new NamespaceEvidence(
                                        EvidenceKind.FACTORY_MAP, mappedNs,
                                        "factory-map: " + methodName + " → " + mappedNs));
                            }
                        }
                    } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable ignored) {}
    }

    /**
     * Looks up the factory method namespace map.
     * Delegates to NamespaceResolver's FACTORY_METHOD_NAMESPACE_MAP (now package-private).
     */
    private static String lookupFactoryMethodNamespaceMap(String methodNameLower) {
        return NamespaceResolver.FACTORY_METHOD_NAMESPACE_MAP.get(methodNameLower);
    }

    private static void extractVariableNameEvidence(CallSiteInfo site) {
        try {
            Set<String> candidates = NamespaceResolver.inferNamespaceFromVariableName(site.receiver);
            for (String ns : candidates) {
                site.evidence.add(new NamespaceEvidence(
                        EvidenceKind.VARIABLE_NAME, ns,
                        "variable-name: " + site.receiver.getName()));
            }
        } catch (Throwable ignored) {}
    }

    private static void extractPathBasedEvidence(CallSiteInfo site) {
        try {
            var info = site.nameInfo;
            if (info == null || !info.valid) return;

            // Evidence 5: ROOT_QUALIFIER — from the resolved name's root qualifier
            if (info.rootQualifier != null && !info.rootQualifier.isEmpty()) {
                String rqLower = info.rootQualifier.toLowerCase(Locale.ROOT);
                boolean isSdkLibrary = rqLower.contains("@ohos") || rqLower.contains("@kit")
                        || rqLower.contains("ohos.") || rqLower.contains("kit.");
                if (!isSdkLibrary) {
                    Set<String> rqCandidates =
                            NamespaceResolver.extractNamespaceCandidatesFromRootQualifier(info.rootQualifier);
                    for (String ns : rqCandidates) {
                        site.evidence.add(new NamespaceEvidence(
                                EvidenceKind.ROOT_QUALIFIER, ns,
                                "root-qualifier: " + info.rootQualifier));
                    }
                }
            }

            // Also check for &...& pattern in joinedPath
            String joinedPath = String.join(".", info.pathTokens);
            if (joinedPath.contains("&")) {
                int start = joinedPath.indexOf('&');
                int end = joinedPath.indexOf('&', start + 1);
                if (end > start) {
                    String rqSource = joinedPath.substring(start + 1, end);
                    String rqLower = rqSource.toLowerCase(Locale.ROOT);
                    boolean isSdkLibrary = rqLower.contains("@ohos") || rqLower.contains("@kit");
                    if (!isSdkLibrary) {
                        Set<String> rqCandidates =
                                NamespaceResolver.extractNamespaceCandidatesFromRootQualifier(rqSource);
                        for (String ns : rqCandidates) {
                            site.evidence.add(new NamespaceEvidence(
                                    EvidenceKind.ROOT_QUALIFIER, ns,
                                    "path-qualifier: " + rqSource));
                        }
                    }
                }
            }

            // Evidence 6: PATH_TOKEN — namespace tokens in the path
            if (info.pathTokens.size() >= 2) {
                // The token immediately before the method token is typically the namespace
                String nsToken = info.pathTokens.get(info.pathTokens.size() - 2);
                if (nsToken != null && !nsToken.isEmpty()
                        && !nsToken.equals("unknown") && !nsToken.equals("Object")) {
                    site.evidence.add(new NamespaceEvidence(
                            EvidenceKind.PATH_TOKEN, nsToken,
                            "path-token[" + (info.pathTokens.size() - 2) + "]: " + nsToken));
                }
            }
        } catch (Throwable ignored) {}
    }

    // ======================================================
    // Phase 2: Alias Component Construction (Union-Find)
    // ======================================================

    /**
     * Builds alias components from call sites using Andersen's comparePointers.
     * Call sites whose receiver variables alias (point to the same object)
     * are grouped into the same alias component and must share a namespace.
     *
     * @param callSites All call sites to process
     * @param andersen Andersen PTA instance (may be null)
     * @return List of alias components
     */
    static List<AliasComponent> buildAliasComponents(
            List<CallSiteInfo> callSites, Andersen andersen) {
        // Collect call sites with non-null receiver variables
        List<CallSiteInfo> sitesWithReceiver = callSites.stream()
                .filter(s -> s.receiver != null)
                .collect(Collectors.toList());

        UnionFind uf = new UnionFind();

        if (andersen != null && sitesWithReceiver.size() > 1) {
            // O(n²) pairwise comparison — acceptable for typical project sizes
            for (int i = 0; i < sitesWithReceiver.size(); i++) {
                for (int j = i + 1; j < sitesWithReceiver.size(); j++) {
                    Local v1 = sitesWithReceiver.get(i).receiver;
                    Local v2 = sitesWithReceiver.get(j).receiver;
                    try {
                        if (andersen.comparePointers(v1, v2)) {
                            uf.union(v1, v2);
                        }
                    } catch (Throwable ignored) {}
                }
            }
        }

        // Group call sites by their root representative
        Map<Local, AliasComponent> rootToComponent = new LinkedHashMap<>();
        List<AliasComponent> components = new ArrayList<>();
        int nextId = 0;

        for (CallSiteInfo site : sitesWithReceiver) {
            Local root = uf.find(site.receiver);
            AliasComponent comp = rootToComponent.get(root);
            if (comp == null) {
                comp = new AliasComponent(nextId++);
                rootToComponent.put(root, comp);
                components.add(comp);
            }
            comp.receiverVars.add(site.receiver);
            comp.callSites.add(site);
            site.aliasComponentId = comp.componentId;
        }

        // Call sites without receiver form singleton components
        for (CallSiteInfo site : callSites) {
            if (site.receiver == null) {
                AliasComponent singleton = new AliasComponent(nextId++);
                singleton.callSites.add(site);
                site.aliasComponentId = singleton.componentId;
                components.add(singleton);
            }
        }

        return components;
    }

    // ======================================================
    // Phase 3: Candidate Generation (All Compatible)
    // ======================================================

    /**
     * Generates ALL compatible API candidates for a call site, not just
     * the first matching rule. Each candidate is scored based on the
     * weighted evidence supporting its namespace.
     *
     * @param site Call site to resolve
     * @param indirectRules Privacy API rules with directCall=false
     * @return List of scored candidates, sorted by score descending
     */
    static List<CandidateApi> generateCandidates(
            CallSiteInfo site,
            List<PreciseSensitiveApiScanner.PrivacyApiRuleWithPkg> indirectRules) {
        List<CandidateApi> candidates = new ArrayList<>();
        String baseMethod = NamePathMatcher.stripMethodArguments(site.methodName);

        for (PreciseSensitiveApiScanner.PrivacyApiRuleWithPkg item : indirectRules) {
            String ruleMethod = NamePathMatcher.stripMethodArguments(item.rule.method);
            if (!baseMethod.equals(ruleMethod)) continue;

            // Method name matches. Check if the evidence supports this rule's namespace.
            double score = computeNamespaceScore(site.evidence, item.rule.namespace);

            // Also check path-based matching
            boolean pathMatch = false;
            if (site.nameInfo != null && site.nameInfo.valid) {
                String joinedPath = String.join(".", site.nameInfo.pathTokens);
                pathMatch = (ruleMethod != null && !ruleMethod.isEmpty()
                        && endsWithDotted(joinedPath, ruleMethod)
                        && NamePathMatcher.namespaceMatchesForMethod(
                            site.nameInfo.pathTokens, ruleMethod, item.rule.namespace));
            }

            // Accept candidate if:
            // 1. Path-based match succeeds (high confidence), OR
            // 2. Evidence score > 0 (some namespace evidence supports this rule), OR
            // 3. Method is unique to a single canonical namespace (heuristic fallback)
            boolean methodUnique = NamespaceResolver.isMethodUniqueToNamespace(baseMethod, indirectRules);
            if (pathMatch || score > 0 || methodUnique) {
                CandidateApi cand = new CandidateApi(
                        item.rule.namespace, ruleMethod, item, score);
                // Boost score for path matches
                if (pathMatch) {
                    cand.score += 1.0;
                }
                // Small baseline score for unique-method heuristic
                if (methodUnique && score == 0 && !pathMatch) {
                    cand.score = 0.1;
                }
                candidates.add(cand);
            }
        }

        // Sort by score descending
        candidates.sort((a, b) -> Double.compare(b.score, a.score));
        return candidates;
    }

    /**
     * Computes the weighted evidence score for a given namespace.
     * Score = sum of evidence weights where the evidence's namespace
     * is compatible with (equals or aliases to) the target namespace.
     */
    static double computeNamespaceScore(List<NamespaceEvidence> evidence, String targetNamespace) {
        double score = 0;
        Set<String> compatible = getCompatibleNamespaces(targetNamespace);
        for (NamespaceEvidence ev : evidence) {
            if (isNamespaceCompatible(ev.namespace, compatible)) {
                score += ev.weight;
            }
        }
        return score;
    }

    /** Gets all namespaces compatible with the target (itself + aliases). */
    static Set<String> getCompatibleNamespaces(String namespace) {
        Set<String> compatible = new HashSet<>();
        if (namespace == null || namespace.isEmpty()) return compatible;
        compatible.add(namespace.toLowerCase(Locale.ROOT));
        // Add PACKAGE_ALIASES
        List<String> aliases = NamespaceResolver.getRulePackagesForImport(namespace);
        for (String alias : aliases) {
            compatible.add(alias.toLowerCase(Locale.ROOT));
            // Also add last segment of dotted aliases
            int dot = alias.lastIndexOf('.');
            if (dot > 0) {
                compatible.add(alias.substring(dot + 1).toLowerCase(Locale.ROOT));
            }
        }
        // Add derived forms for @ohos.xxx / @kit.xxx
        for (String ns : new HashSet<>(compatible)) {
            String withoutAt = ns.startsWith("@") ? ns.substring(1) : ns;
            compatible.add(withoutAt);
            int dot = withoutAt.lastIndexOf('.');
            if (dot > 0) {
                compatible.add(withoutAt.substring(dot + 1));
            }
        }
        return compatible;
    }

    /** Checks if a candidate namespace is compatible with any of the compatible set. */
    private static boolean isNamespaceCompatible(String candidate, Set<String> compatibleLower) {
        if (candidate == null || candidate.isEmpty()) return false;
        String candidateLower = candidate.toLowerCase(Locale.ROOT);
        if (compatibleLower.contains(candidateLower)) return true;
        // Prefix/suffix match
        for (String compat : compatibleLower) {
            if (compat.startsWith(candidateLower) || candidateLower.startsWith(compat)) {
                return true;
            }
        }
        return false;
    }

    // ======================================================
    // Phase 4: Joint Constraint Solving per Alias Component
    // ======================================================

    /** Maximum number of call sites in a component before falling back to majority vote. */
    private static final int LARGE_COMPONENT_THRESHOLD = 10;

    /**
     * Solves namespace constraints per alias component.
     * Within a component, all call sites must share the same namespace.
     * The optimal namespace assignment maximizes the total evidence score.
     *
     * For small components (≤10 sites): enumerate all compatible namespace assignments.
     * For large components: majority vote fallback.
     */
    static void solveConstraints(
            List<AliasComponent> components,
            List<PreciseSensitiveApiScanner.PrivacyApiRuleWithPkg> indirectRules) {
        for (AliasComponent comp : components) {
            // Generate candidates for each call site
            List<List<CandidateApi>> siteCandidates = new ArrayList<>();
            for (CallSiteInfo site : comp.callSites) {
                List<CandidateApi> cands = generateCandidates(site, indirectRules);
                site.allCandidates = cands;
                siteCandidates.add(cands);
            }

            // Collect all candidate namespaces across the component
            Set<String> allNamespaces = new LinkedHashSet<>();
            for (List<CandidateApi> cands : siteCandidates) {
                for (CandidateApi cand : cands) {
                    allNamespaces.add(cand.namespace);
                }
            }
            comp.candidateNamespaces = allNamespaces;

            if (comp.callSites.size() > LARGE_COMPONENT_THRESHOLD || allNamespaces.size() > 8) {
                // Fallback: majority vote — each site picks its best namespace,
                // then the component uses the most popular namespace.
                solveByMajorityVote(comp, siteCandidates);
            } else if (comp.callSites.size() == 1) {
                // Singleton: pick the best candidate
                solveSingleton(comp, siteCandidates);
            } else {
                // Full enumeration
                solveByEnumeration(comp, siteCandidates, allNamespaces);
            }
        }
    }

    private static void solveSingleton(AliasComponent comp, List<List<CandidateApi>> siteCandidates) {
        CallSiteInfo site = comp.callSites.get(0);
        List<CandidateApi> cands = siteCandidates.get(0);
        if (!cands.isEmpty()) {
            // Best candidate is already first (sorted by score desc)
            site.evidence.addAll(extractEvidenceForSite(site));
        }
    }

    private static void solveByMajorityVote(AliasComponent comp, List<List<CandidateApi>> siteCandidates) {
        // Each site votes for its best namespace
        Map<String, Double> namespaceVotes = new LinkedHashMap<>();
        for (int i = 0; i < comp.callSites.size(); i++) {
            List<CandidateApi> cands = siteCandidates.get(i);
            if (!cands.isEmpty()) {
                String bestNs = cands.get(0).namespace;
                double bestScore = cands.get(0).score;
                namespaceVotes.merge(bestNs, bestScore, Double::sum);
            }
        }

        // Pick the namespace with highest total votes
        String winnerNs = null;
        double winnerScore = -1;
        for (Map.Entry<String, Double> entry : namespaceVotes.entrySet()) {
            if (entry.getValue() > winnerScore) {
                winnerScore = entry.getValue();
                winnerNs = entry.getKey();
            }
        }

        // Reassign: for each site, pick the candidate matching the winning namespace
        if (winnerNs != null) {
            Set<String> compatibleWinner = getCompatibleNamespaces(winnerNs);
            for (int i = 0; i < comp.callSites.size(); i++) {
                List<CandidateApi> cands = siteCandidates.get(i);
                // Find best candidate matching winner
                CandidateApi best = null;
                for (CandidateApi cand : cands) {
                    if (isNamespaceCompatible(cand.namespace, compatibleWinner)) {
                        best = cand;
                        break; // Already sorted by score
                    }
                }
                // If no candidate matches winner, keep the original best
                if (best == null && !cands.isEmpty()) {
                    best = cands.get(0);
                }
                // Store the assignment in the candidate list (keep only the winner)
                if (best != null) {
                    siteCandidates.set(i, List.of(best));
                }
            }
        }
    }

    private static void solveByEnumeration(AliasComponent comp,
                                           List<List<CandidateApi>> siteCandidates,
                                           Set<String> allNamespaces) {
        // Enumerate namespace assignments: each site gets assigned one of allNamespaces.
        // Constraint: all sites in the same component must share the same namespace.
        // So we just need to find the namespace that maximizes the total score.

        List<String> nsList = new ArrayList<>(allNamespaces);
        String bestNs = null;
        double bestTotalScore = Double.NEGATIVE_INFINITY;

        for (String ns : nsList) {
            Set<String> compatible = getCompatibleNamespaces(ns);
            double totalScore = 0;
            boolean allSitesCovered = true;

            for (int i = 0; i < comp.callSites.size(); i++) {
                List<CandidateApi> cands = siteCandidates.get(i);
                double siteBestScore = 0;
                boolean found = false;
                for (CandidateApi cand : cands) {
                    if (isNamespaceCompatible(cand.namespace, compatible)) {
                        siteBestScore = Math.max(siteBestScore, cand.score);
                        found = true;
                    }
                }
                if (!found) {
                    allSitesCovered = false;
                    // Penalty for sites that don't support this namespace
                    siteBestScore = -1.0;
                }
                totalScore += siteBestScore;
            }

            if (totalScore > bestTotalScore) {
                bestTotalScore = totalScore;
                bestNs = ns;
            }
        }

        // Reassign candidates based on the winning namespace
        if (bestNs != null) {
            Set<String> compatibleBest = getCompatibleNamespaces(bestNs);
            for (int i = 0; i < comp.callSites.size(); i++) {
                List<CandidateApi> cands = siteCandidates.get(i);
                CandidateApi best = null;
                for (CandidateApi cand : cands) {
                    if (isNamespaceCompatible(cand.namespace, compatibleBest)) {
                        best = cand;
                        break;
                    }
                }
                // If no candidate matches the winning namespace, keep original best
                if (best == null && !cands.isEmpty()) {
                    best = cands.get(0);
                }
                if (best != null) {
                    siteCandidates.set(i, List.of(best));
                }
            }
        }
    }

    // ======================================================
    // Phase 5: Ambiguity-Aware Abstention
    // ======================================================

    /**
     * Assesses ambiguity for each resolution result using entropy.
     * Replaces the binary GENERIC_METHOD_BLACKLIST with continuous ambiguity measurement.
     *
     * Entropy H = -Σ p_i * log2(p_i) where p_i = score_i / Σ score_j
     * H > threshold → mark as ambiguous (keep the match but flag low confidence)
     *
     * @param results Resolution results to assess
     */
    static void assessAmbiguity(List<ResolutionResult> results) {
        for (ResolutionResult result : results) {
            List<CandidateApi> cands = result.allCandidates;
            if (cands == null || cands.isEmpty()) {
                result.isAmbiguous = true;
                result.entropy = Double.MAX_VALUE;
                continue;
            }

            // Group candidates by canonical namespace
            Map<String, Double> nsScores = new LinkedHashMap<>();
            for (CandidateApi cand : cands) {
                String canonicalNs = getCanonicalNamespaceKey(cand.namespace);
                nsScores.merge(canonicalNs, cand.score, Double::sum);
            }

            if (nsScores.size() <= 1) {
                // Unique namespace — no ambiguity
                result.entropy = 0.0;
                result.isAmbiguous = false;
                continue;
            }

            // Compute entropy
            double totalScore = nsScores.values().stream().mapToDouble(Double::doubleValue).sum();
            if (totalScore <= 0) {
                result.entropy = 0.0;
                result.isAmbiguous = false;
                continue;
            }

            double entropy = 0;
            for (double score : nsScores.values()) {
                double p = score / totalScore;
                if (p > 0) {
                    entropy -= p * (Math.log(p) / Math.log(2));
                }
            }
            result.entropy = entropy;

            // Check if strong evidence (PTA_CLASS or STATIC_TYPE) is present
            boolean hasStrongEvidence = result.callSite.evidence.stream()
                    .anyMatch(ev -> ev.kind == EvidenceKind.PTA_CLASS || ev.kind == EvidenceKind.STATIC_TYPE);

            // Use AmbiguityModel which considers both entropy and inherent method ambiguity
            result.isAmbiguous = AmbiguityModel.isAmbiguous(
                    entropy, result.callSite.methodName, hasStrongEvidence);

            // Also check namespace contradiction: if all evidence contradicts the best candidate,
            // mark as ambiguous. This mirrors the old isNamespaceContradicted logic.
            if (!result.isAmbiguous && result.bestCandidate != null) {
                Set<String> namespaceCandidates = result.callSite.evidence.stream()
                        .map(ev -> ev.namespace)
                        .filter(ns -> ns != null && !ns.isEmpty())
                        .collect(Collectors.toSet());
                if (!namespaceCandidates.isEmpty()) {
                    boolean contradicted = NamespaceResolver.isNamespaceContradicted(
                            namespaceCandidates, result.bestCandidate.namespace);
                    if (contradicted) {
                        result.isAmbiguous = true;
                        result.entropy = Math.max(result.entropy, 2.0);
                    }
                }
            }
        }
    }

    /**
     * Gets a canonical namespace key that collapses aliases.
     * Delegates to NamespaceResolver.getCanonicalNamespace (now package-private).
     */
    static String getCanonicalNamespaceKey(String ns) {
        return NamespaceResolver.getCanonicalNamespace(ns != null ? ns.toLowerCase(Locale.ROOT) : ns);
    }

    // ======================================================
    // Phase 6: Resolution Certificate
    // ======================================================

    /**
     * Generates resolution certificates for each result.
     * Each certificate contains the contributing evidence, alias component ID,
     * and a human-readable decision rationale.
     */
    static void generateCertificates(List<ResolutionResult> results) {
        for (ResolutionResult result : results) {
            CallSiteInfo site = result.callSite;
            List<NamespaceEvidence> contributing = new ArrayList<>();

            if (result.bestCandidate != null) {
                // Collect evidence that supports the chosen namespace
                Set<String> compatible = getCompatibleNamespaces(result.bestCandidate.namespace);
                for (NamespaceEvidence ev : site.evidence) {
                    if (isNamespaceCompatible(ev.namespace, compatible)) {
                        contributing.add(ev);
                    }
                }
            }

            // Sort contributing evidence by weight descending
            contributing.sort((a, b) -> Double.compare(b.weight, a.weight));

            String rationale = buildRationale(result, contributing);
            result.certificate = new ResolutionCertificate(
                    contributing, site.aliasComponentId, rationale);
        }
    }

    private static String buildRationale(ResolutionResult result, List<NamespaceEvidence> contributing) {
        StringBuilder sb = new StringBuilder();
        if (result.bestCandidate != null) {
            sb.append("Resolved to ").append(result.bestCandidate.namespace)
              .append(".").append(result.bestCandidate.methodName);
            if (!contributing.isEmpty()) {
                sb.append(" via ");
                for (int i = 0; i < contributing.size(); i++) {
                    if (i > 0) sb.append(", ");
                    NamespaceEvidence ev = contributing.get(i);
                    sb.append(ev.kind).append("(").append(String.format("%.1f", ev.weight)).append(")");
                }
            }
            if (result.isAmbiguous) {
                sb.append(" [AMBIGUOUS: entropy=").append(String.format("%.2f", result.entropy)).append("]");
            }
        } else {
            sb.append("No matching candidate found");
        }
        return sb.toString();
    }

    // ======================================================
    // Main Resolution Pipeline
    // ======================================================

    /**
     * Resolves all indirect calls in a HiFile using the CAIR algorithm.
     *
     * Pipeline: extract evidence → build alias components → generate candidates →
     * solve constraints → assess ambiguity → generate certificates
     *
     * @param callSiteData List of (stmt, resolvedName, fileName, functionName) for indirect calls
     * @param indirectRules Privacy API rules with directCall=false
     * @param andersen Andersen PTA instance (may be null)
     * @param cg Call graph (may be null)
     * @param hiFile HiFile being analyzed (may be null)
     * @return Map from Stmt to ResolutionResult
     */
    public static Map<Stmt, ResolutionResult> resolve(
            List<Object[]> callSiteData,
            List<PreciseSensitiveApiScanner.PrivacyApiRuleWithPkg> indirectRules,
            Andersen andersen,
            CallGraph cg,
            HiFile hiFile) {

        // Step 1: Build CallSiteInfo objects
        List<CallSiteInfo> callSites = new ArrayList<>();
        for (Object[] data : callSiteData) {
            Stmt stmt = (Stmt) data[0];
            String resolvedName = (String) data[1];
            String fileName = (String) data[2];
            String functionName = (String) data[3];

            PreciseSensitiveApiScanner.ResolvedNameInfo nameInfo =
                    NamePathMatcher.parseResolvedName(resolvedName);

            // Extract receiver and method name from the statement
            Local receiver = null;
            String methodName = nameInfo.lastToken;
            if (stmt instanceof CallStmt) {
                try {
                    var callExpr = ((CallStmt) stmt).getCallExpr();
                    if (callExpr instanceof com.huawei.hianalyzer.ir.value.expr.InstanceCallExpr) {
                        var ice = (com.huawei.hianalyzer.ir.value.expr.InstanceCallExpr) callExpr;
                        receiver = ice.getBase();
                        // Method name comes from the resolved name info, not the call expression
                    }
                } catch (Throwable ignored) {}
            }

            CallSiteInfo site = new CallSiteInfo(stmt, receiver, methodName,
                    resolvedName, nameInfo, fileName, functionName);
            callSites.add(site);
        }

        // Step 2: Extract evidence for each call site
        for (CallSiteInfo site : callSites) {
            extractEvidence(site, andersen, cg);
        }

        // Step 3: Build alias components
        List<AliasComponent> components = buildAliasComponents(callSites, andersen);

        // Step 4: Generate candidates and solve constraints
        solveConstraints(components, indirectRules);

        // Step 5: Build resolution results
        Map<Stmt, ResolutionResult> resultMap = new LinkedHashMap<>();
        List<ResolutionResult> allResults = new ArrayList<>();
        for (CallSiteInfo site : callSites) {
            ResolutionResult result = new ResolutionResult(site);
            // Get the resolved candidate from site.allCandidates
            // After constraint solving, each site's candidates list should have
            // been filtered to the winning namespace's candidates
            if (!site.allCandidates.isEmpty()) {
                result.bestCandidate = site.allCandidates.get(0);
            }
            result.allCandidates = new ArrayList<>(site.allCandidates);
            allResults.add(result);
            resultMap.put(site.stmt, result);
        }

        // Step 6: Assess ambiguity
        assessAmbiguity(allResults);

        // Step 7: Generate certificates
        generateCertificates(allResults);

        return resultMap;
    }

    /**
     * Converts a ResolutionResult to a SensitiveApiHit for integration
     * with the existing scanner output.
     */
    public static PreciseSensitiveApiScanner.SensitiveApiHit toSensitiveApiHit(
            ResolutionResult result, String layer, String sourceKind) {
        if (result.bestCandidate == null) return null;

        PreciseSensitiveApiScanner.SensitiveApiHit hit = new PreciseSensitiveApiScanner.SensitiveApiHit();
        hit.layer = layer;
        hit.category = "indirect invoke";
        hit.sourceKind = sourceKind;
        hit.systemPackage = result.bestCandidate.rule.systemPackage;
        hit.namespace = result.bestCandidate.namespace;
        hit.method = result.bestCandidate.rule.rule.method; // Keep original (with args)
        hit.permission = result.bestCandidate.rule.rule.permission;
        hit.profilingCategory = result.bestCandidate.rule.rule.profilingCategory;
        hit.dataDirection = result.bestCandidate.rule.rule.dataDirection;
        hit.matchedFullName = result.callSite.resolvedFullName;
        hit.stmtObj = result.callSite.stmt;
        hit.file = result.callSite.fileName;
        hit.function = result.callSite.functionName;
        hit.confidence = result.isAmbiguous ? "low" : "high";

        // Add certificate info to stmtText for traceability
        String stmtText = safe(result.callSite.stmt);
        if (result.certificate != null) {
            stmtText = stmtText + " [CAIR:" + result.certificate.decisionRationale + "]";
        }
        hit.stmtText = stmtText;

        return hit;
    }

    // ======================================================
    // Utility methods
    // ======================================================

    private static String safe(Stmt stmt) {
        if (stmt == null) return "";
        try {
            String s = stmt.toString();
            return s != null ? s : "";
        } catch (Throwable t) {
            return "ERROR: " + safeMessage(t);
        }
    }

    private static String safeMessage(Throwable t) {
        if (t == null) return "null";
        try {
            String msg = t.getMessage();
            return msg != null ? msg : t.getClass().getSimpleName();
        } catch (Throwable t2) {
            return t.getClass().getSimpleName();
        }
    }

    /**
     * Checks if a dotted path ends with a given method pattern.
     * E.g., "audio.getAudioManager" endsWithDotted "getAudioManager"
     */
    static boolean endsWithDotted(String path, String method) {
        if (path == null || method == null) return false;
        return path.equals(method) || path.endsWith("." + method);
    }

    // ======================================================
    // Evidence extraction helper (for extractEvidence access)
    // ======================================================

    /**
     * Extracts raw namespace evidence for a call site (Phase 1 helper).
     * Returns the evidence directly, used for certificate generation.
     */
    private static List<NamespaceEvidence> extractEvidenceForSite(CallSiteInfo site) {
        return new ArrayList<>(site.evidence);
    }
}
