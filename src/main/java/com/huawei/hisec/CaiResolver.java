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

    /** Conflict penalty factor. Evidence pointing to an incompatible namespace
     *  subtracts gamma * weight from the candidate's score.
     *  Score(c,a) = Σ w_e(support) - γ * Σ w_e(conflict) */
    public static double CONFLICT_PENALTY_GAMMA = 0.5;

    /** Penalty for a call site whose assigned namespace differs from the
     *  component's majority namespace. Allows outlier sites with a penalty
     *  instead of forcing incorrect namespace assignment.
     *  Objective: max Σ Score(c,a_c) - λ * Σ o_c
     *  Soft-alias edges are logged for diagnostics but do not affect the objective. */
    public static double CONSISTENCY_PENALTY_LAMBDA = 1.0;

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
        public final String stmtText;  // Cached for argument-sensitive matching

        // Populated during alias component construction
        int aliasComponentId = -1;

        // Populated during candidate generation and constraint solving
        List<CandidateApi> allCandidates = new ArrayList<>();

        // Populated after constraint solving — the solver's winner
        // (separate from allCandidates to keep the full candidate list for entropy computation)
        CandidateApi assignedCandidate = null;
        boolean isOutlier = false;  // True if this site's assignment diverges from component namespace
        String componentNamespace = null;  // The component's chosen namespace

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
            this.stmtText = safe(stmt);
        }
    }

    /** Type-consistent component: set of receiver variables with identical singleton
     *  class types, strongly suggesting they share the same namespace. */
    public static class AliasComponent {
        public final int componentId;
        public final Set<Local> receiverVars = new LinkedHashSet<>();
        public final List<CallSiteInfo> callSites = new ArrayList<>();
        public Set<String> candidateNamespaces = new LinkedHashSet<>();
        public String selectedNamespace;  // Namespace chosen by joint solver

        public AliasComponent(int componentId) {
            this.componentId = componentId;
        }
    }

    /** Soft alias edge: two variables with overlapping points-to sets
     *  but different singleton types (type-overlapping). These are not hard constraints
     *  but are logged for diagnostic analysis when their namespaces agree.
     *  Note: True must-alias (proving two receivers are the same object) requires
     *  allocation-site-level points-to sets, which HiAnalyzer's Andersen PTA does not
     *  expose. We use "type-consistent" as the strongest alias claim we can make. */
    public static class SoftAliasEdge {
        public final Local v1, v2;
        public SoftAliasEdge(Local v1, Local v2) { this.v1 = v1; this.v2 = v2; }
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
        public List<NamespaceEvidence> conflictingEvidence;  // Evidence arguing against
        public int aliasComponentId;
        public String componentNamespace;      // The component's chosen namespace
        public String decisionRationale;
        public List<String> rejectionReasons;  // Why alternatives were rejected

        public ResolutionCertificate(List<NamespaceEvidence> contributingEvidence,
                                     List<NamespaceEvidence> conflictingEvidence,
                                     int aliasComponentId, String componentNamespace,
                                     String decisionRationale,
                                     List<String> rejectionReasons) {
            this.contributingEvidence = contributingEvidence;
            this.conflictingEvidence = conflictingEvidence;
            this.aliasComponentId = aliasComponentId;
            this.componentNamespace = componentNamespace;
            this.decisionRationale = decisionRationale;
            this.rejectionReasons = rejectionReasons;
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

            // Collect class names already covered by PTA evidence to avoid double-counting.
            // If PTA_CLASS already produced evidence for the same HiClass, STATIC_TYPE
            // would duplicate the same namespace observation with a lower weight (0.8 vs 1.0),
            // inflating the total score for that namespace.
            Set<String> ptaClassNames = site.evidence.stream()
                    .filter(e -> e.kind == EvidenceKind.PTA_CLASS)
                    .map(e -> e.detail.replace("points-to: ", ""))
                    .collect(Collectors.toSet());

            if (type instanceof InstanceType) {
                try {
                    var classRef = ((InstanceType) type).getClassRef();
                    if (classRef != null) {
                        BaseClass<?, ?> cls = classRef.resolve();
                        if (cls != null) {
                            // Skip if PTA already covered this class
                            if (ptaClassNames.contains(cls.getName())) {
                                return;  // Avoid double-counting with PTA_CLASS evidence
                            }
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

            // Collect namespaces already added by earlier evidence extraction
            // to avoid double-counting (e.g., ROOT_QUALIFIER and PATH_TOKEN
            // producing the same namespace from the same underlying observation).
            Set<String> existingNamespaces = site.evidence.stream()
                    .map(e -> e.namespace != null ? e.namespace.toLowerCase(Locale.ROOT) : "")
                    .filter(ns -> !ns.isEmpty())
                    .collect(Collectors.toSet());

            // Evidence 5: ROOT_QUALIFIER — from the resolved name's root qualifier
            Set<String> rootQualifierNamespaces = new LinkedHashSet<>();
            if (info.rootQualifier != null && !info.rootQualifier.isEmpty()) {
                String rqLower = info.rootQualifier.toLowerCase(Locale.ROOT);
                boolean isSdkLibrary = rqLower.contains("@ohos") || rqLower.contains("@kit")
                        || rqLower.contains("ohos.") || rqLower.contains("kit.");
                if (!isSdkLibrary) {
                    Set<String> rqCandidates =
                            NamespaceResolver.extractNamespaceCandidatesFromRootQualifier(info.rootQualifier);
                    for (String ns : rqCandidates) {
                        String nsLower = ns.toLowerCase(Locale.ROOT);
                        if (!existingNamespaces.contains(nsLower)) {
                            site.evidence.add(new NamespaceEvidence(
                                    EvidenceKind.ROOT_QUALIFIER, ns,
                                    "root-qualifier: " + info.rootQualifier));
                            rootQualifierNamespaces.add(nsLower);
                            existingNamespaces.add(nsLower);
                        }
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
                            String nsLower = ns.toLowerCase(Locale.ROOT);
                            if (!existingNamespaces.contains(nsLower)) {
                                site.evidence.add(new NamespaceEvidence(
                                        EvidenceKind.ROOT_QUALIFIER, ns,
                                        "path-qualifier: " + rqSource));
                                rootQualifierNamespaces.add(nsLower);
                                existingNamespaces.add(nsLower);
                            }
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
                    String nsLower = nsToken.toLowerCase(Locale.ROOT);
                    // Skip if ROOT_QUALIFIER or earlier evidence already covers this namespace
                    if (!existingNamespaces.contains(nsLower)) {
                        site.evidence.add(new NamespaceEvidence(
                                EvidenceKind.PATH_TOKEN, nsToken,
                                "path-token[" + (info.pathTokens.size() - 2) + "]: " + nsToken));
                        existingNamespaces.add(nsLower);
                    }
                }
            }
        } catch (Throwable ignored) {}
    }

    // ======================================================
    // Phase 2: Alias Component Construction (Union-Find)
    // ======================================================

    /**
     * Builds alias components from call sites using Andersen's comparePointers.
     * Distinguishes receiver-type-consistent (identical singleton points-to CLASS sets)
     * from type-overlapping (aliasing but potentially different concrete types).
     *
     * Type-consistent: variables are unioned into the same component (they provably
     *   share the same runtime class type, though not necessarily the same object).
     * Type-overlapping: recorded as soft edges for diagnostic analysis (not a hard constraint).
     *
     * Note: True must-alias (proving two receivers are the same object) requires
     * allocation-site-level points-to sets, which HiAnalyzer's Andersen PTA does not
     * expose. We use "type-consistent" as the strongest alias claim we can make.
     *
     * @param callSites All call sites to process
     * @param andersen Andersen PTA instance (may be null)
     * @return AliasComponentResult containing components and soft edges
     */
    static AliasComponentResult buildAliasComponents(
            List<CallSiteInfo> callSites, Andersen andersen) {
        // Collect call sites with non-null receiver variables
        List<CallSiteInfo> sitesWithReceiver = callSites.stream()
                .filter(s -> s.receiver != null)
                .collect(Collectors.toList());

        UnionFind uf = new UnionFind();
        List<SoftAliasEdge> softEdges = new ArrayList<>();

        if (andersen != null && sitesWithReceiver.size() > 1) {
            // Pre-compute points-to class names for all receivers to avoid
            // redundant PTA queries in the O(n²) pairwise comparison loop
            Map<Local, Set<String>> receiverPtClasses = new LinkedHashMap<>();
            for (CallSiteInfo site : sitesWithReceiver) {
                receiverPtClasses.put(site.receiver, getPointsToClassNames(site.receiver, andersen));
            }

            // O(n²) pairwise comparison — acceptable for typical project sizes
            for (int i = 0; i < sitesWithReceiver.size(); i++) {
                for (int j = i + 1; j < sitesWithReceiver.size(); j++) {
                    Local v1 = sitesWithReceiver.get(i).receiver;
                    Local v2 = sitesWithReceiver.get(j).receiver;
                    try {
                        if (andersen.comparePointers(v1, v2)) {
                            // Distinguish type-consistent from type-overlapping:
                            // Type-consistent: both receivers have identical singleton points-to CLASS sets
                            //   (same runtime type, but not necessarily same object)
                            // Type-overlapping: aliasing with potentially different concrete types
                            Set<String> pt1 = receiverPtClasses.get(v1);
                            Set<String> pt2 = receiverPtClasses.get(v2);
                            if (pt1 != null && pt2 != null
                                    && pt1.size() == 1 && pt2.size() == 1 && pt1.equals(pt2)) {
                                // Type-consistent: same single concrete type → merge into component
                                uf.union(v1, v2);
                            } else {
                                // Type-overlapping: aliasing with potentially different types → soft edge (diagnostic)
                                softEdges.add(new SoftAliasEdge(v1, v2));
                            }
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

        return new AliasComponentResult(components, softEdges);
    }

    /** Result of alias component construction: components + soft edges. */
    public static class AliasComponentResult {
        public final List<AliasComponent> components;
        public final List<SoftAliasEdge> softEdges;
        public AliasComponentResult(List<AliasComponent> components, List<SoftAliasEdge> softEdges) {
            this.components = components;
            this.softEdges = softEdges;
        }
    }

    /** Gets the class names in a variable's points-to set. */
    private static Set<String> getPointsToClassNames(Local v, Andersen andersen) {
        try {
            Set<HiClass> pts = andersen.getPointsToHiClasses(v);
            if (pts == null) return Collections.emptySet();
            return pts.stream().map(cls -> cls.getName()).collect(Collectors.toSet());
        } catch (Throwable e) { return Collections.emptySet(); }
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

            // Argument-sensitive matching: if the rule has parenthesized arguments
            // (e.g., "on('SensorId.ACCELEROMETER')"), check if the call site's
            // arguments match the expected pattern. This prevents collapsing
            // different argument-variant rules into a single candidate.
            String ruleArg = NamePathMatcher.extractMethodArgument(item.rule.method);
            if (ruleArg != null && !ruleArg.isEmpty()) {
                if (!callSiteArgsMatch(site.stmt, site.stmtText, ruleArg)) {
                    continue;  // Argument doesn't match — skip this specific rule variant
                }
            }

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
            // 3. Method is unique to a single canonical namespace
            //    (generic verbs like request/stop/register are also accepted here,
            //     but will be flagged by the ambiguity assessment in Phase 5 —
            //     the same approach as the old matchIndirectCall heuristic which
            //     only blocks when there is NO namespace evidence at all)
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
     * Computes the conflict-aware weighted evidence score for a given namespace.
     * Score(c,a) = Σ w_e(support) - γ * Σ w_e(conflict)
     * Supporting evidence: namespace compatible with target.
     * Conflicting evidence: namespace present but incompatible with target.
     */
    static double computeNamespaceScore(List<NamespaceEvidence> evidence, String targetNamespace) {
        double supportScore = 0;
        double conflictScore = 0;
        Set<String> compatible = getCompatibleNamespaces(targetNamespace);
        for (NamespaceEvidence ev : evidence) {
            if (isNamespaceCompatible(ev.namespace, compatible)) {
                supportScore += ev.weight;
            } else if (ev.namespace != null && !ev.namespace.isEmpty()) {
                // Evidence points to a different, incompatible namespace.
                // PTA_CLASS evidence is "possible" (not exclusive) — discount conflict by 50%.
                // STATIC_TYPE, ROOT_QUALIFIER, PATH_TOKEN are "exclusive" — full conflict penalty.
                double conflictWeight = (ev.kind == EvidenceKind.PTA_CLASS) ? ev.weight * 0.5 : ev.weight;
                conflictScore += conflictWeight;
            }
        }
        return supportScore - CONFLICT_PENALTY_GAMMA * conflictScore;
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

    /** Checks if a candidate namespace is compatible with any of the compatible set.
     *  Uses canonical namespace comparison instead of overly broad prefix matching. */
    private static boolean isNamespaceCompatible(String candidate, Set<String> compatibleLower) {
        if (candidate == null || candidate.isEmpty()) return false;
        String candidateLower = candidate.toLowerCase(Locale.ROOT);
        // Direct match
        if (compatibleLower.contains(candidateLower)) return true;
        // Canonical namespace comparison: check if they share the same canonical form
        String candidateCanonical = getCanonicalNamespaceKey(candidateLower);
        for (String compat : compatibleLower) {
            if (getCanonicalNamespaceKey(compat).equals(candidateCanonical)) return true;
        }
        // Also check PACKAGE_ALIASES for the candidate
        List<String> candidateAliases = NamespaceResolver.getRulePackagesForImport(candidate);
        for (String alias : candidateAliases) {
            if (compatibleLower.contains(alias.toLowerCase(Locale.ROOT))) return true;
        }
        return false;
    }

    // ======================================================
    // Phase 4: Joint Constraint Solving per Alias Component
    // ======================================================

    // Component-label aggregation (solveByEnumeration) is O(K * N * C) where
    // K=namespaces, N=call sites, C=candidates per site. Always tractable —
    // no fallback needed.

    /**
     * Solves namespace constraints per alias component.
     * Within a component (type-consistent receivers), call sites should share the same namespace.
     * Outliers are allowed with a consistency penalty (soft consistency).
     * Soft alias edges (type-overlapping) are logged for diagnostic analysis.
     *
     * Objective: max Σ Score(c,a_c) - λ * Σ o_c + bonus * soft_agreements
     *
     * For small components (≤10 sites): enumerate all compatible namespace assignments.
     * For large components: majority vote fallback.
     */
    static void solveConstraints(
            List<AliasComponent> components,
            List<PreciseSensitiveApiScanner.PrivacyApiRuleWithPkg> indirectRules,
            List<SoftAliasEdge> softEdges,
            List<CallSiteInfo> allCallSites) {
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

            if (comp.callSites.size() == 1) {
                // Singleton: pick the best candidate
                solveSingleton(comp, siteCandidates);
            } else {
                // Component-label aggregation: O(K * N * C) — always tractable
                solveByEnumeration(comp, siteCandidates, allNamespaces);
            }
        }

        // Log soft-alias edge outcomes for diagnostic analysis (does not affect scores).
        // Soft-alias edges are type-overlapping receivers whose namespace agreement
        // is informative but does not participate in the joint objective.
        if (!softEdges.isEmpty()) {
            Map<Local, String> receiverToNamespace = new LinkedHashMap<>();
            for (CallSiteInfo site : allCallSites) {
                if (site.receiver != null && site.assignedCandidate != null) {
                    receiverToNamespace.put(site.receiver, site.assignedCandidate.namespace);
                }
            }
            for (SoftAliasEdge edge : softEdges) {
                String ns1 = receiverToNamespace.get(edge.v1);
                String ns2 = receiverToNamespace.get(edge.v2);
                if (ns1 != null && ns2 != null) {
                    Set<String> compatible = getCompatibleNamespaces(ns1);
                    boolean agrees = isNamespaceCompatible(ns2, compatible);
                    Logger.log("  [CAIR] Soft-alias " + edge.v1.getName() + " -- " + edge.v2.getName()
                            + " ns1=" + ns1 + " ns2=" + ns2 + " agree=" + agrees);
                }
            }
        }
    }

    private static void solveSingleton(AliasComponent comp, List<List<CandidateApi>> siteCandidates) {
        CallSiteInfo site = comp.callSites.get(0);
        List<CandidateApi> cands = siteCandidates.get(0);
        if (!cands.isEmpty()) {
            // Best candidate is already first (sorted by score desc)
            site.assignedCandidate = cands.get(0);
            // Evidence was already extracted in Phase 1 (extractEvidence at Step 2)
        }
    }

    private static void solveByEnumeration(AliasComponent comp,
                                           List<List<CandidateApi>> siteCandidates,
                                           Set<String> allNamespaces) {
        // Enumerate namespace assignments: for each candidate namespace z,
        // compute the total objective: Σ_i f_i(z) where
        //   f_i(z) = max(best_same_ns_score, best_other_ns_score - λ)
        // This allows a site to "outlier" — use its best candidate from a
        // different namespace at a consistency penalty.
        // Complexity: O(K * N * C) — always tractable.

        List<String> nsList = new ArrayList<>(allNamespaces);
        String bestNs = null;
        double bestTotalScore = Double.NEGATIVE_INFINITY;

        for (String ns : nsList) {
            Set<String> compatible = getCompatibleNamespaces(ns);
            double totalScore = 0;

            for (int i = 0; i < comp.callSites.size(); i++) {
                List<CandidateApi> cands = siteCandidates.get(i);
                double bestSameNs = Double.NEGATIVE_INFINITY;
                double bestOtherNs = Double.NEGATIVE_INFINITY;

                for (CandidateApi cand : cands) {
                    if (isNamespaceCompatible(cand.namespace, compatible)) {
                        bestSameNs = Math.max(bestSameNs, cand.score);
                    } else {
                        bestOtherNs = Math.max(bestOtherNs, cand.score);
                    }
                }

                // Outlier formula: site can use best other-ns candidate at a penalty
                double siteScore;
                if (bestSameNs > Double.NEGATIVE_INFINITY) {
                    siteScore = Math.max(bestSameNs,
                            bestOtherNs > Double.NEGATIVE_INFINITY
                                    ? bestOtherNs - CONSISTENCY_PENALTY_LAMBDA
                                    : Double.NEGATIVE_INFINITY);
                } else if (bestOtherNs > Double.NEGATIVE_INFINITY) {
                    // No same-ns candidate; must use other-ns with penalty
                    siteScore = bestOtherNs - CONSISTENCY_PENALTY_LAMBDA;
                } else {
                    // No candidates at all for this site
                    siteScore = -CONSISTENCY_PENALTY_LAMBDA;
                }

                totalScore += siteScore;
            }

            if (totalScore > bestTotalScore) {
                bestTotalScore = totalScore;
                bestNs = ns;
            }
        }

        // Reassign candidates based on the winning namespace.
        // Each site must execute the same outlier comparison used in the objective:
        //   f_i(z) = max(bestSameNs, bestOtherNs - λ)
        // If outlierUtility > sameUtility, the site is an outlier and keeps its
        // own best candidate from a different namespace.
        if (bestNs != null) {
            Set<String> compatibleBest = getCompatibleNamespaces(bestNs);
            comp.selectedNamespace = bestNs;
            for (CallSiteInfo site : comp.callSites) {
                site.componentNamespace = bestNs;
            }
            for (int i = 0; i < comp.callSites.size(); i++) {
                List<CandidateApi> cands = siteCandidates.get(i);

                CandidateApi bestSame = null;
                CandidateApi bestOther = null;

                for (CandidateApi cand : cands) {
                    if (isNamespaceCompatible(cand.namespace, compatibleBest)) {
                        if (bestSame == null) bestSame = cand;
                    } else {
                        if (bestOther == null) bestOther = cand;
                    }
                }

                // Execute the outlier comparison from the objective function
                double sameUtility = (bestSame != null) ? bestSame.score : Double.NEGATIVE_INFINITY;
                double outlierUtility = (bestOther != null) ? bestOther.score - CONSISTENCY_PENALTY_LAMBDA : Double.NEGATIVE_INFINITY;

                if (outlierUtility > sameUtility && bestOther != null) {
                    // Outlier: site's best other-ns candidate is better than same-ns after penalty
                    comp.callSites.get(i).assignedCandidate = bestOther;
                    comp.callSites.get(i).isOutlier = true;
                } else if (bestSame != null) {
                    // Non-outlier: component namespace candidate is best
                    comp.callSites.get(i).assignedCandidate = bestSame;
                    comp.callSites.get(i).isOutlier = false;
                } else if (bestOther != null) {
                    // No same-ns candidate at all — must use other-ns
                    comp.callSites.get(i).assignedCandidate = bestOther;
                    comp.callSites.get(i).isOutlier = true;
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

            // Pre-compute evidence flags (needed for both single and multi-namespace cases)
            // Strong evidence requires ALL PTA/STATIC_TYPE evidence to point to the same
            // canonical namespace AND that namespace must support the bestCandidate.
            Set<String> strongNamespaces = result.callSite.evidence.stream()
                    .filter(ev -> ev.kind == EvidenceKind.PTA_CLASS || ev.kind == EvidenceKind.STATIC_TYPE)
                    .map(ev -> NamespaceResolver.getCanonicalNamespace(
                            ev.namespace != null ? ev.namespace.toLowerCase(Locale.ROOT) : ""))
                    .filter(ns -> ns != null && !ns.isEmpty())
                    .collect(Collectors.toSet());
            boolean hasStrongEvidence = false;
            if (strongNamespaces.size() == 1 && result.bestCandidate != null) {
                // The unique strong namespace must support the best candidate
                String strongNs = strongNamespaces.iterator().next();
                Set<String> candidateCompatible = getCompatibleNamespaces(result.bestCandidate.namespace);
                hasStrongEvidence = isNamespaceCompatible(strongNs, candidateCompatible);
            }
            boolean hasAnyEvidence = !result.callSite.evidence.isEmpty();
            String strippedMethod = NamePathMatcher.stripMethodArguments(result.callSite.methodName);

            // Check if any evidence actually supports the best candidate's namespace.
            // This is more precise than hasAnyEvidence: evidence may exist but be unrelated
            // to the chosen namespace (e.g., evidence points to "CalendarManager" but
            // the methodUnique fallback chose "HttpRequest.request").
            boolean hasSupportingEvidence = false;
            if (result.bestCandidate != null) {
                Set<String> compatible = getCompatibleNamespaces(result.bestCandidate.namespace);
                hasSupportingEvidence = result.callSite.evidence.stream()
                        .anyMatch(ev -> isNamespaceCompatible(ev.namespace, compatible));
            }

            // Group candidates by canonical namespace
            Map<String, Double> nsScores = new LinkedHashMap<>();
            for (CandidateApi cand : cands) {
                String canonicalNs = getCanonicalNamespaceKey(cand.namespace);
                nsScores.merge(canonicalNs, cand.score, Double::sum);
            }

            if (nsScores.size() <= 1) {
                // Unique namespace candidate. Normally no ambiguity,
                // but must still pass absolute score threshold.
                result.entropy = 0.0;
                result.isAmbiguous = false;

                // Absolute score threshold: even single-namespace candidates must have
                // sufficient confidence. A score of 0.1 with only one namespace is unreliable.
                if (result.bestCandidate != null
                        && result.bestCandidate.score < AmbiguityModel.MIN_CONFIDENCE) {
                    result.isAmbiguous = true;
                    result.entropy = 2.0;
                    Logger.log("  [CAIR] Ambiguous (low score=" + String.format("%.2f", result.bestCandidate.score)
                            + " < MIN_CONFIDENCE=" + AmbiguityModel.MIN_CONFIDENCE
                            + ", single namespace): "
                            + strippedMethod + " -> " + result.bestCandidate.namespace);
                    continue;
                }

                // Check: inherently ambiguous method + no SUPPORTING evidence + low score = block
                boolean isGeneric = AmbiguityModel.isInherentlyAmbiguous(strippedMethod);
                if (isGeneric && !hasSupportingEvidence && result.bestCandidate != null
                        && result.bestCandidate.score <= 0.1) {
                    result.isAmbiguous = true;
                    result.entropy = 2.0;
                    Logger.log("  [CAIR] Ambiguous (no supporting evidence, generic method): "
                            + strippedMethod + " -> " + result.bestCandidate.namespace);
                }
                continue;
            }

            // Compute entropy using softmax normalization (handles negative scores correctly)
            // Softmax: p_i = exp(s_i - max_s) / Σ exp(s_j - max_s)
            // This ensures all probabilities are positive and sum to 1, even when
            // conflict penalties produce negative candidate scores.
            double maxScore = nsScores.values().stream()
                    .mapToDouble(Double::doubleValue).max().orElse(0);
            double sumExp = 0;
            for (double score : nsScores.values()) {
                sumExp += Math.exp(score - maxScore);  // numerical stability: subtract max
            }

            double entropy = 0;
            for (double score : nsScores.values()) {
                double p = Math.exp(score - maxScore) / sumExp;
                if (p > 1e-10) {
                    entropy -= p * (Math.log(p) / Math.log(2));
                }
            }
            result.entropy = entropy;

            // Use AmbiguityModel which considers both entropy and inherent method ambiguity
            result.isAmbiguous = AmbiguityModel.isAmbiguous(
                    entropy, strippedMethod, hasStrongEvidence);

            // Absolute score threshold: if the best candidate has very low score,
            // the resolution is unreliable regardless of entropy
            if (!result.isAmbiguous && result.bestCandidate != null
                    && result.bestCandidate.score < AmbiguityModel.MIN_CONFIDENCE) {
                result.isAmbiguous = true;
                result.entropy = Math.max(result.entropy, 2.0);
                Logger.log("  [CAIR] Ambiguous (low score=" + String.format("%.2f", result.bestCandidate.score)
                        + " < MIN_CONFIDENCE=" + AmbiguityModel.MIN_CONFIDENCE + "): "
                        + strippedMethod + " -> " + result.bestCandidate.namespace);
            }

            // Margin check: if top-1 and top-2 scores are too close, resolution is ambiguous
            if (!result.isAmbiguous && nsScores.size() >= 2) {
                List<Double> sortedScores = nsScores.values().stream()
                        .sorted(Comparator.reverseOrder()).collect(Collectors.toList());
                double margin = sortedScores.get(0) - sortedScores.get(1);
                if (margin < AmbiguityModel.MARGIN_THRESHOLD) {
                    result.isAmbiguous = true;
                    result.entropy = Math.max(result.entropy, 1.5);
                    Logger.log("  [CAIR] Ambiguous (small margin=" + String.format("%.2f", margin)
                            + " < MARGIN_THRESHOLD=" + AmbiguityModel.MARGIN_THRESHOLD + "): "
                            + strippedMethod);
                }
            }

            // Additional block: for inherently ambiguous methods (request, stop, register, etc.)
            // with NO namespace evidence at all, always mark as ambiguous.
            // This matches the old matchIndirectCall's GENERIC_METHOD_BLACKLIST logic:
            //   if (GENERIC_METHOD_BLACKLIST.contains(method) && !hasPtaCandidates && namespaceCandidates.isEmpty())
            if (!result.isAmbiguous && AmbiguityModel.isInherentlyAmbiguous(strippedMethod)
                    && !hasSupportingEvidence && result.bestCandidate != null && result.bestCandidate.score <= 0.1) {
                result.isAmbiguous = true;
                result.entropy = Math.max(result.entropy, 2.0);
                Logger.log("  [CAIR] Ambiguous (no supporting evidence, generic method, multi-ns): "
                        + strippedMethod + " -> " + result.bestCandidate.namespace);
            }

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
     * Each certificate contains contributing evidence, conflicting evidence,
     * alias component ID, and a human-readable decision rationale.
     */
    static void generateCertificates(List<ResolutionResult> results) {
        for (ResolutionResult result : results) {
            CallSiteInfo site = result.callSite;
            List<NamespaceEvidence> contributing = new ArrayList<>();
            List<NamespaceEvidence> conflicting = new ArrayList<>();
            List<String> rejectionReasons = new ArrayList<>();
            String componentNs = null;

            if (result.bestCandidate != null) {
                // Collect evidence that supports vs conflicts with the chosen namespace
                Set<String> compatible = getCompatibleNamespaces(result.bestCandidate.namespace);
                for (NamespaceEvidence ev : site.evidence) {
                    if (isNamespaceCompatible(ev.namespace, compatible)) {
                        contributing.add(ev);
                    } else if (ev.namespace != null && !ev.namespace.isEmpty()) {
                        conflicting.add(ev);
                    }
                }
                // For outlier sites, componentNs is the component's namespace (not the
                // assigned candidate's namespace); for non-outliers they are the same.
                componentNs = site.isOutlier ? findComponentNamespace(site) : result.bestCandidate.namespace;

                // Build rejection reasons for top alternatives
                if (result.allCandidates.size() > 1) {
                    // The winner may not be allCandidates[0] after joint solving
                    CandidateApi winner = result.bestCandidate;
                    for (CandidateApi alt : result.allCandidates) {
                        if (alt != winner && rejectionReasons.size() < 3) {
                            rejectionReasons.add(String.format("Rejected %s.%s (score=%.2f vs winner %.2f)",
                                    alt.namespace, alt.methodName, alt.score,
                                    winner.score));
                        }
                    }
                }
            }

            // Sort evidence by weight descending
            contributing.sort((a, b) -> Double.compare(b.weight, a.weight));
            conflicting.sort((a, b) -> Double.compare(b.weight, a.weight));

            String rationale = buildRationale(result, contributing, conflicting);
            result.certificate = new ResolutionCertificate(
                    contributing, conflicting, site.aliasComponentId,
                    componentNs, rationale, rejectionReasons);
        }
    }

    /** Find the component's selected namespace for a given call site. */
    private static String findComponentNamespace(CallSiteInfo site) {
        // Walk through the site's component to find the selected namespace
        // This is set during solveByEnumeration
        return site.componentNamespace;
    }

    private static String buildRationale(ResolutionResult result,
                                          List<NamespaceEvidence> contributing,
                                          List<NamespaceEvidence> conflicting) {
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
            if (!conflicting.isEmpty()) {
                sb.append(" [conflict:");
                for (int i = 0; i < Math.min(conflicting.size(), 2); i++) {
                    if (i > 0) sb.append(",");
                    NamespaceEvidence ev = conflicting.get(i);
                    sb.append(" ").append(ev.kind).append("→").append(ev.namespace);
                }
                sb.append("]");
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

        // Step 0: Analyze rule catalog for catalog-derived ambiguity assessment
        // and pre-compute method uniqueness cache
        AmbiguityModel.analyzeCatalog(indirectRules);
        NamespaceResolver.precomputeMethodUniqueness(indirectRules);

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

        // Step 3: Build alias components (distinguishing type-consistent vs type-overlapping)
        AliasComponentResult acResult = buildAliasComponents(callSites, andersen);
        List<AliasComponent> components = acResult.components;
        List<SoftAliasEdge> softEdges = acResult.softEdges;

        // Step 4: Generate candidates and solve constraints
        solveConstraints(components, indirectRules, softEdges, callSites);

        // Step 5: Build resolution results
        Map<Stmt, ResolutionResult> resultMap = new LinkedHashMap<>();
        List<ResolutionResult> allResults = new ArrayList<>();
        for (CallSiteInfo site : callSites) {
            ResolutionResult result = new ResolutionResult(site);
            // Use the constraint solver's winner (assignedCandidate) if available,
            // otherwise fall back to the first candidate from allCandidates.
            // allCandidates is kept unchanged for entropy/ambiguity computation.
            if (site.assignedCandidate != null) {
                result.bestCandidate = site.assignedCandidate;
            } else if (!site.allCandidates.isEmpty()) {
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

    /**
     * Checks if the call site's arguments match the expected argument pattern.
     * Mirrors PreciseSensitiveApiScanner.callStmtArgsMatchArgumentPattern()
     * but as a static method accessible from CaiResolver.
     */
    static boolean callSiteArgsMatch(Stmt stmt, String stmtText, String expectedArg) {
        if (expectedArg == null || expectedArg.isEmpty()) return true;

        // Primary: extract StringConstant arguments from the CallStmt IR
        if (stmt instanceof CallStmt) {
            try {
                var callExpr = ((CallStmt) stmt).getCallExpr();
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
            } catch (Throwable ignored) {}
        }

        // Fallback: check stmtText for the expected argument pattern
        String argTail = expectedArg.contains(".")
                ? expectedArg.substring(expectedArg.lastIndexOf('.') + 1) : expectedArg;
        if (stmtText == null) return false;
        if (stmtText.contains(expectedArg)) return true;
        if (argTail.length() >= 3 && stmtText.contains(argTail)) return true;
        return false;
    }

    /**
     * Checks whether an actual argument value matches the expected argument pattern.
     * Supports exact match and suffix match for enum-qualified patterns.
     */
    private static boolean argumentMatchesPattern(String actualArg, String expectedArg) {
        if (actualArg == null || expectedArg == null) return false;
        if (actualArg.equals(expectedArg)) return true;
        String expectedTail = expectedArg.contains(".")
                ? expectedArg.substring(expectedArg.lastIndexOf('.') + 1) : expectedArg;
        if (actualArg.equals(expectedTail)) return true;
        if (actualArg.equalsIgnoreCase(expectedTail)) return true;
        if (actualArg.contains(expectedArg)) return true;
        return false;
    }

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
}
