package com.huawei.hisec;

import com.huawei.hianalyzer.common.base.BaseClass;
import com.huawei.hianalyzer.analysis.base.HiClass;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.graph.callgraph.pta.andersen.Andersen;
import com.huawei.hianalyzer.common.type.InstanceType;
import com.huawei.hianalyzer.common.type.Type;
import com.huawei.hianalyzer.analysis.base.HiFunction;
import com.huawei.hianalyzer.ir.stmt.CallStmt;
import com.huawei.hianalyzer.ir.stmt.Stmt;
import com.huawei.hianalyzer.ir.value.Local;

import java.util.*;

/**
 * Resolves namespace candidates for indirect call matching.
 *
 * When an InstanceCallExpr is encountered (e.g., mgr.getAudioScene()),
 * the namespace of the API must be inferred from the base variable's type.
 * This class implements multiple strategies:
 *
 * Strategy 1: Andersen PTA points-to analysis
 * Strategy 2: Static type from Local.getType()
 * Strategy 3: Factory method return type via FunctionRef.getReturnType()
 *
 * Also provides namespace contradiction checking and alias resolution.
 */
public class NamespaceResolver {

    // ======================================================
    // HarmonyOS SDK namespace aliases
    // ======================================================

    /**
     * HarmonyOS SDK namespace aliases: maps each namespace to its equivalent
     * alternative names. In HarmonyOS, the same API can be imported via
     * different namespace paths (e.g., @ohos.geoLocationManager vs
     * @kit.LocationKit). When matching rules, we must accept any alias.
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

    // ======================================================
    // Main entry: infer namespace candidates from call base
    // ======================================================

    /**
     * Infers namespace candidates for an InstanceCallExpr by examining the base variable.
     * Uses three strategies in order: PTA, static type, factory method return type.
     *
     * @param stmt    The statement containing the InstanceCallExpr
     * @param andersen Andersen PTA instance (may be null)
     * @return Set of namespace candidate strings
     */
    public static Set<String> inferNamespaceCandidatesFromCallBase(Stmt stmt, Andersen andersen) {
        Set<String> candidates = new LinkedHashSet<>();

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
                            Set<HiClass> ptClasses =
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
                        // If the type is InstanceType, resolve to HiClass for richer extraction
                        // (class name, package name, ForeignClass metadata) instead of just
                        // taking the first segment of type.toString().
                        if (type instanceof InstanceType) {
                            try {
                                var classRef = ((InstanceType) type).getClassRef();
                                if (classRef != null) {
                                    BaseClass<?, ?> cls = classRef.resolve();
                                    if (cls != null) {
                                        candidates.addAll(extractNamespaceCandidatesFromClass(cls));
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
                                candidates.add(ns);
                            }
                        }
                    }

                    // Strategy 3: Trace the base variable's assignment to find factory method return type.
                    // When PTA can't resolve factory methods (e.g., getAudioManager() -> AudioManager),
                    // we trace back to the assignment statement and use FunctionRef.getReturnType()
                    // to get the declared return type from SDK metadata.
                    if (candidates.isEmpty()) {
                        candidates.addAll(inferNamespaceFromAssignment(base, stmt, andersen));
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return candidates;
    }

    // ======================================================
    // Strategy 3: Factory method return type inference
    // ======================================================

    /**
     * Infers namespace candidates by tracing the base variable's assignment back to
     * a factory method call and extracting the declared return type via FunctionRef.
     *
     * This handles the common HarmonyOS pattern where:
     *   let mgr = getAudioManager();  // factory method returns AudioManager
     *   mgr.getAudioScene()           // InstanceCallExpr on mgr
     *
     * Andersen PTA cannot resolve the type of mgr because getAudioManager()'s
     * implementation is in the SDK (not in the analyzed binary). However, the
     * FunctionRef on the assignment CallStmt carries the declared return type
     * from SDK metadata, which we can use directly.
     */
    static Set<String> inferNamespaceFromAssignment(Local base, Stmt usageStmt, Andersen andersen) {
        Set<String> candidates = new LinkedHashSet<>();
        try {
            List<Stmt> defStmts = findDefinitionStmts(base, usageStmt, andersen);
            for (Stmt defStmt : defStmts) {
                if (defStmt instanceof CallStmt) {
                    CallStmt defCall = (CallStmt) defStmt;
                    try {
                        var callExpr = defCall.getCallExpr();
                        if (callExpr != null) {
                            var funcRef = callExpr.getFunctionRef();
                            if (funcRef != null) {
                                var returnType = funcRef.getReturnType();
                                if (returnType != null) {
                                    candidates.addAll(
                                            extractNamespaceCandidatesFromReturnType(returnType));
                                }
                            }
                        }
                    } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable ignored) {}
        return candidates;
    }

    /**
     * Finds the statements that define (assign to) the given Local variable.
     * Two strategies:
     * 1. Andersen PTA's getPointsToStmts() — returns statements that assign
     *    values to the local's points-to set.
     * 2. Manual scan of the containing function's body — finds CallStmts
     *    whose LValue (result variable) matches the target Local.
     */
    static List<Stmt> findDefinitionStmts(Local base, Stmt usageStmt, Andersen andersen) {
        // Strategy A: Use PTA's points-to analysis.
        if (andersen != null) {
            try {
                Set<Stmt> pts = andersen.getPointsToStmts(base);
                if (pts != null && !pts.isEmpty()) {
                    return new ArrayList<>(pts);
                }
            } catch (Throwable ignored) {}
        }

        // Strategy B: Scan the containing function's statements.
        // Collect ALL CallStmts whose LValue matches the target Local,
        // not just the first one — a variable may be assigned in multiple
        // branches (e.g., conditional or phi-node patterns).
        List<Stmt> results = new ArrayList<>();
        try {
            HiFunction func = usageStmt.getHiFunction();
            if (func != null && func.getBody() != null) {
                var stmts = func.getBody().getStmts();
                if (stmts != null) {
                    for (Stmt s : stmts) {
                        if (s instanceof CallStmt) {
                            CallStmt cs = (CallStmt) s;
                            try {
                                var lValue = cs.getLValue();
                                if (lValue != null && lValue == base) {
                                    results.add(s);
                                }
                            } catch (Throwable ignored) {}
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}

        return results;
    }

    // ======================================================
    // Namespace extraction from types
    // ======================================================

    /**
     * Extracts namespace candidates from a BaseClass object (HiClass extends BaseClass).
     * Returns both the class name and the last segment of the package name,
     * since rules use either as the namespace (e.g., "HttpRequest" or "deviceinfo").
     */
    static Set<String> extractNamespaceCandidatesFromClass(BaseClass<?, ?> cls) {
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
     */
    static Set<String> extractNamespaceCandidatesFromRootQualifier(String rootQualifier) {
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
     * Extracts namespace candidates from a Type object, typically the return type
     * of a factory method obtained via FunctionRef.getReturnType().
     *
     * Handles:
     * - InstanceType: resolves to BaseClass, extracts class name, package name,
     *   and ForeignClass metadata (importName, fromPath).
     * - Generic fallback: uses type.toString() to extract the first segment.
     */
    static Set<String> extractNamespaceCandidatesFromReturnType(Type returnType) {
        Set<String> candidates = new LinkedHashSet<>();
        if (returnType == null) return candidates;

        try {
            // Handle InstanceType: resolve to BaseClass and extract namespace.
            if (returnType instanceof InstanceType) {
                InstanceType instType = (InstanceType) returnType;
                var classRef = instType.getClassRef();
                if (classRef != null) {
                    BaseClass<?, ?> cls = classRef.resolve();
                    if (cls != null) {
                        // Reuse extractNamespaceCandidatesFromClass for consistent extraction
                        candidates.addAll(extractNamespaceCandidatesFromClass(cls));
                    }
                }
            }

            // Generic fallback: use type's string representation.
            String typeStr = returnType.toString();
            if (typeStr != null && !typeStr.isEmpty()) {
                int dot = typeStr.indexOf('.');
                String ns = dot > 0 ? typeStr.substring(0, dot) : typeStr;
                if (!ns.isEmpty() && !ns.equals("unknown") && !ns.equals("Object")) {
                    candidates.add(ns);
                }
            }
        } catch (Throwable ignored) {}

        return candidates;
    }

    // ======================================================
    // PTA-based method check
    // ======================================================

    /**
     * Checks if any PTA-resolved class for the call's base variable has a method
     * with the given name. If the PTA class itself defines this method, the call
     * is to the class's own implementation, not to an SDK API via dynamic dispatch.
     * This is used to prevent false positives like UserViewModel.register being
     * matched as NetConnection.register.
     */
    public static boolean ptaClassHasMethod(Stmt stmt, Andersen andersen, String methodName) {
        if (!(stmt instanceof CallStmt) || andersen == null || methodName == null) {
            return false;
        }
        try {
            CallStmt callStmt = (CallStmt) stmt;
            var callExpr = callStmt.getCallExpr();
            if (callExpr instanceof com.huawei.hianalyzer.ir.value.expr.InstanceCallExpr) {
                var base = ((com.huawei.hianalyzer.ir.value.expr.InstanceCallExpr) callExpr).getBase();
                if (base != null) {
                    Set<HiClass> ptClasses =
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
                            // Check superclass chain — the method may be defined in a parent class
                            // rather than the PTA-resolved class itself.
                            // cls is HiClass which has getSuperClass() returning BaseClass<?,?>.
                            // To traverse the chain, we cast back to HiClass since getSuperClass()
                            // is defined on HiClass, not BaseClass.
                            try {
                                HiClass current = cls;
                                while (true) {
                                    BaseClass<?, ?> superClass = current.getSuperClass();
                                    if (superClass == null) break;
                                    var superFuncs = superClass.getFunctionByName(methodName);
                                    if (superFuncs != null && !superFuncs.isEmpty()) {
                                        return true;
                                    }
                                    // Continue up the chain if superClass is also a HiClass
                                    if (superClass instanceof HiClass) {
                                        current = (HiClass) superClass;
                                    } else {
                                        break;
                                    }
                                }
                            } catch (Throwable ignored) {}
                            // Check implemented interfaces
                            try {
                                var interfaces = cls.getInterfaceClasses();
                                if (interfaces != null) {
                                    for (var iface : interfaces) {
                                        var ifaceFuncs = iface.getFunctionByName(methodName);
                                        if (ifaceFuncs != null && !ifaceFuncs.isEmpty()) {
                                            return true;
                                        }
                                    }
                                }
                            } catch (Throwable ignored) {}
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    // ======================================================
    // Namespace selection and contradiction
    // ======================================================

    /**
     * When multiple namespace candidates are found via PTA, pick the best one.
     * Prefers namespaces that match known API module patterns (e.g., containing
     * "ohos", "kit", or common SDK identifiers).
     */
    public static String pickBestNamespace(Set<String> namespaces) {
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
     * Checks whether ALL inferred namespace candidates contradict the rule's namespace.
     * A candidate contradicts if it is non-empty, not equal to the rule namespace,
     * not a prefix/suffix of it, and not an alias of it.
     * If ANY candidate is compatible (including via PACKAGE_ALIASES), we return false
     * (no contradiction). If no candidates exist, we also return false (no evidence
 * of contradiction, so allow the heuristic match).
     */
    public static boolean isNamespaceContradicted(Set<String> candidates, String ruleNamespace) {
        if (candidates == null || candidates.isEmpty()) {
            return false; // No evidence → don't block
        }
        // Build a set of all names compatible with the rule namespace (including aliases).
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

    /**
     * Checks if a method name uniquely identifies a single namespace among the given rules.
     * This is used as a heuristic fallback: if only one rule has this method name,
     * we can safely match by method name alone even without namespace confirmation.
     */
    public static boolean isMethodUniqueToNamespace(String method, List<PreciseSensitiveApiScanner.PrivacyApiRuleWithPkg> indirectRules) {
        if (method == null || indirectRules == null) {
            return false;
        }
        int count = 0;
        for (PreciseSensitiveApiScanner.PrivacyApiRuleWithPkg item : indirectRules) {
            String baseMethod = NamePathMatcher.stripMethodArguments(item.rule.method);
            if (method.equals(baseMethod)) {
                count++;
                if (count > 1) {
                    return false;
                }
            }
        }
        return count == 1;
    }

    /**
     * Gets all package names that are equivalent to the given package,
     * including the package itself and all its aliases.
     */
    public static List<String> getRulePackagesForImport(String pkg) {
        List<String> result = new ArrayList<>();
        result.add(pkg);
        List<String> aliases = PACKAGE_ALIASES.get(pkg);
        if (aliases != null) {
            result.addAll(aliases);
        }
        return result;
    }

    // ======================================================
    // Namespace validation against HiFile
    // ======================================================

    /**
     * Validates whether the inferred namespace corresponds to a real class in the HiFile.
     * Uses HiFile.getHiClassesByNameAndPackageName() to check if any class with
     * the given name or package exists in the analyzed binary or its dependencies.
     *
     * @param namespace The inferred namespace to validate
     * @param hiFile    The HiFile being analyzed
     * @return true if the namespace matches a known class or package
     */
    public static boolean namespaceExistsInHiFile(String namespace, HiFile hiFile) {
        if (namespace == null || hiFile == null) return false;
        try {
            // Try exact name match
            var classes = hiFile.getHiClassesByNameAndPackageName(namespace, null);
            if (classes != null && !classes.isEmpty()) return true;
            // Try as package name
            var pkgClasses = hiFile.getHiClassesByNameAndPackageName(null, namespace);
            if (pkgClasses != null && !pkgClasses.isEmpty()) return true;
        } catch (Throwable ignored) {}
        return false;
    }

    /**
     * Checks if a namespace is a known HarmonyOS SDK namespace.
     * SDK namespaces contain "ohos" or "kit" markers, or appear as keys
     * in the PACKAGE_ALIASES mapping.
     *
     * @param namespace The namespace to check
     * @return true if this is a known SDK namespace
     */
    public static boolean isKnownSdkNamespace(String namespace) {
        if (namespace == null) return false;
        String lower = namespace.toLowerCase(Locale.ROOT);
        return lower.contains("ohos") || lower.contains("kit") || PACKAGE_ALIASES.containsKey(namespace);
    }
}
