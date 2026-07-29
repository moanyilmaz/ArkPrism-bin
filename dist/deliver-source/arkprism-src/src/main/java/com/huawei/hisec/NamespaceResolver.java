package com.huawei.hisec;

import com.huawei.hianalyzer.common.base.BaseClass;
import com.huawei.hianalyzer.analysis.base.HiClass;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.graph.callgraph.CallGraph;
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
            Map.entry("identifier", List.of("oaid")),
            // Class-to-module aliases: privacy_apis.json uses both the class name
            // (e.g., SystemPasteboard) and the module name (e.g., pasteboard) as
            // the namespace for the same API. These must be treated as equivalent.
            Map.entry("SystemPasteboard", List.of("pasteboard", "@ohos.pasteboard")),
            Map.entry("pasteboard", List.of("SystemPasteboard", "@ohos.pasteboard")),
            // Class-to-module aliases: connection APIs use NetConnection as class name
            // in the binary, but the rule namespace is "connection".
            Map.entry("NetConnection", List.of("connection", "@ohos.net.connection")),
            Map.entry("connection", List.of("NetConnection", "@ohos.net.connection")),
            // Class-to-module aliases: userAuth APIs use UserAuth as class name
            // in the binary, but the rule namespace is "userAuth".
            Map.entry("UserAuth", List.of("userAuth", "@ohos.userIAM.userAuth")),
            Map.entry("userAuth", List.of("UserAuth", "@ohos.userIAM.userAuth"))
    );

    // ======================================================
    // HarmonyOS SDK factory method → namespace mapping
    // ======================================================

    /**
     * Maps factory method names to their corresponding namespace.
     * When Andersen PTA cannot resolve the type of objects returned by
     * SDK factory methods (because the implementation is in the SDK, not
     * in the analyzed app), this mapping provides a hardcoded fallback.
     *
     * For example, audio.getAudioManager() returns an AudioManager object,
     * but PTA can't infer this because getAudioManager()'s body is external.
     * This map tells us that getAudioManager → "audio" namespace.
     *
     * Key: factory method name (lowercase, without namespace prefix)
     * Value: namespace of the returned object's API methods
     */
    // Package-private: accessible by CaiResolver
    static final Map<String, String> FACTORY_METHOD_NAMESPACE_MAP = Map.ofEntries(
            // audio module
            Map.entry("getaudiomanager", "audio"),
            Map.entry("createaudiostream", "audio"),
            Map.entry("createaudiorenderer", "audio"),
            Map.entry("createaudiocapturer", "audio"),
            Map.entry("createringtone", "audio"),
            // camera module
            Map.entry("getcameramanager", "camera"),
            Map.entry("createcamerainput", "camera"),
            Map.entry("createpreviewoutput", "camera"),
            Map.entry("createphotooutput", "camera"),
            Map.entry("createvideooutput", "camera"),
            Map.entry("createcapturesession", "camera"),
            // pasteboard module
            Map.entry("getsystempasteboard", "pasteboard"),
            Map.entry("createpastedata", "pasteboard"),
            Map.entry("createpasterecord", "pasteboard"),
            // network module
            Map.entry("getdefaultnet", "connection"),
            Map.entry("getallnets", "connection"),
            Map.entry("getnetcapabilities", "connection"),
            Map.entry("getconnectionproperties", "connection"),
            // telephony module
            Map.entry("getdefaultcellulardataslotid", "telephony"),
            Map.entry("getdefaultsimslotid", "telephony"),
            Map.entry("getdefaultvoiceslotid", "telephony"),
            // wifi module
            Map.entry("getwifilocalmac", "wifiManager"),
            Map.entry("getlinkedinfo", "wifiManager"),
            Map.entry("getscaninfosync", "wifiManager"),
            Map.entry("getscaninfos", "wifiManager"),
            // bluetooth module
            Map.entry("getprofileproxy", "bluetooth"),
            Map.entry("getprofileinstance", "bluetooth"),
            // location module
            Map.entry("getcachedlocation", "geoLocationManager"),
            Map.entry("getcurrentlocation", "geoLocationManager"),
            // display module
            Map.entry("getdefaultdisplaysync", "display"),
            Map.entry("getdefaultdisplay", "display"),
            Map.entry("getalldisplays", "display"),
            // sensor module
            Map.entry("subscribesensor", "sensor"),
            Map.entry("unsubscribesensor", "sensor"),
            // distributed device manager
            Map.entry("createdevicemanager", "distributedDeviceManager")
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
    public static Set<String> inferNamespaceCandidatesFromCallBase(Stmt stmt, Andersen andersen, CallGraph cg) {
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
                        candidates.addAll(inferNamespaceFromAssignment(base, stmt, andersen, cg));
                    }

                    // Strategy 4: Hardcoded factory method → namespace mapping.
                    // When all dynamic strategies (PTA, static type, FunctionRef return type)
                    // fail to produce namespace candidates, use a hardcoded map of known
                    // HarmonyOS SDK factory methods to their corresponding namespaces.
                    // This handles the common pattern: let mgr = getAudioManager(); mgr.getAudioScene()
                    // where the factory method body is in the SDK and PTA cannot infer the return type.
                    if (candidates.isEmpty()) {
                        candidates.addAll(inferNamespaceFromFactoryMethodMap(base, stmt, andersen, cg));
                    }

                    // Strategy 5: Variable name heuristic.
                    // HarmonyOS coding conventions typically name variables after their type
                    // (e.g., audioManager, cameraManager, systemPasteboard). When all other
                    // strategies fail, check if the base variable's name contains a recognizable
                    // namespace hint. This is a last-resort heuristic to avoid FN on indirect calls
                    // where the factory method definition is in a different function body.
                    if (candidates.isEmpty()) {
                        candidates.addAll(inferNamespaceFromVariableName(base));
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
    static Set<String> inferNamespaceFromAssignment(Local base, Stmt usageStmt, Andersen andersen, CallGraph cg) {
        Set<String> candidates = new LinkedHashSet<>();
        try {
            List<Stmt> defStmts = findDefinitionStmts(base, usageStmt, andersen, cg);
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
    static List<Stmt> findDefinitionStmts(Local base, Stmt usageStmt, Andersen andersen, CallGraph cg) {
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

        if (!results.isEmpty()) {
            return results;
        }

        // Strategy C: Inter-procedural search via CallGraph.
        // When the base variable is not defined in the current function,
        // it may be a function parameter or a class field. Search for
        // factory method calls in the calling functions (callers of the
        // current function) that could have produced the base variable.
        // This handles the common HarmonyOS pattern:
        //   function aboutToAppear() { this.audioManager = getAudioManager(); }
        //   function someMethod() { this.audioManager.getAudioScene(); }
        if (cg != null) {
            try {
                HiFunction currentFunc = usageStmt.getHiFunction();
                if (currentFunc != null) {
                    // Search callers for factory method calls
                    Set<Stmt> callerDefs = findFactoryMethodDefsInCallers(
                            base, currentFunc, cg);
                    if (!callerDefs.isEmpty()) {
                        return new ArrayList<>(callerDefs);
                    }
                }
            } catch (Throwable ignored) {}
        }

        return results;
    }

    /**
     * Searches for factory method definitions in the callers of the given function.
     * This handles the case where a variable is assigned in one function and used
     * in another (e.g., class field initialization in aboutToAppear() and usage
     * in a callback method).
     *
     * For each caller of currentFunc, we look for CallStmts that assign to a
     * variable whose name matches the base variable's name (since it's likely
     * a class field accessed via 'this').
     */
    private static Set<Stmt> findFactoryMethodDefsInCallers(
            Local base, HiFunction currentFunc, CallGraph cg) {
        Set<Stmt> results = new LinkedHashSet<>();
        String baseName = base.getName();
        if (baseName == null || baseName.isEmpty()) return results;

        try {
            if (cg == null) return results;

            // Find all functions that call currentFunc
            Set<HiFunction> callers = new HashSet<>();
            try {
                callers = cg.getCallersByCallee(currentFunc);
                if (callers == null) callers = new HashSet<>();
            } catch (Throwable ignored) {
                callers = new HashSet<>();
            }

            // In each caller, look for CallStmts whose LValue name matches
            // the base variable name (for field access patterns like this.audioManager)
            for (HiFunction caller : callers) {
                if (caller == null || caller.getBody() == null) continue;
                var stmts = caller.getBody().getStmts();
                if (stmts == null) continue;
                for (Stmt s : stmts) {
                    if (s instanceof CallStmt) {
                        CallStmt cs = (CallStmt) s;
                        try {
                            var lValue = cs.getLValue();
                            if (lValue != null) {
                                String lvName = lValue.getName();
                                // Match if the LValue name is the same as the base name
                                // (handles field access via this.x where IR uses the field name)
                                if (baseName.equals(lvName)) {
                                    results.add(s);
                                }
                                // Also match if the LValue is a field access expression
                                // containing the base name
                                String lvStr = lValue.toString();
                                if (lvStr != null && lvStr.contains(baseName)) {
                                    results.add(s);
                                }
                            }
                        } catch (Throwable ignored) {}
                    }
                }
            }
        } catch (Throwable ignored) {}
        return results;
    }

    // ======================================================
    // Strategy 4: Hardcoded factory method → namespace mapping
    // ======================================================

    /**
     * Infers namespace candidates by finding the factory method that assigned
     * the base variable, then looking up the method name in a hardcoded map.
     *
     * This is the last-resort strategy when PTA, static type, and FunctionRef
     * return type all fail. It works by:
     * 1. Finding the definition statements for the base variable (same as Strategy 3)
     * 2. Extracting the method name from the definition's CallStmt
     * 3. Looking up the method name in FACTORY_METHOD_NAMESPACE_MAP
     *
     * For example, if the definition is:
     *   audioManager = @ohos.multimedia.audio.getAudioManager()
     * This extracts "getAudioManager", maps it to "audio", and returns {"audio"}.
     */
    static Set<String> inferNamespaceFromFactoryMethodMap(Local base, Stmt usageStmt, Andersen andersen, CallGraph cg) {
        Set<String> candidates = new LinkedHashSet<>();
        try {
            List<Stmt> defStmts = findDefinitionStmts(base, usageStmt, andersen, cg);
            for (Stmt defStmt : defStmts) {
                if (defStmt instanceof CallStmt) {
                    CallStmt defCall = (CallStmt) defStmt;
                    try {
                        var callExpr = defCall.getCallExpr();
                        if (callExpr != null) {
                            // Try to get the method name from the call expression
                            String methodName = extractMethodNameFromCallExpr(callExpr);
                            if (methodName != null && !methodName.isEmpty()) {
                                String lookupKey = methodName.toLowerCase(Locale.ROOT);
                                String mappedNs = FACTORY_METHOD_NAMESPACE_MAP.get(lookupKey);
                                if (mappedNs != null) {
                                    candidates.add(mappedNs);
                                }
                            }
                        }
                    } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable ignored) {}
        return candidates;
    }

    // ======================================================
    // Strategy 5: Variable name heuristic
    // ======================================================

    /**
     * Infers namespace candidates from the base variable's name.
     * HarmonyOS developers commonly name variables after the API class they hold:
     *   audioManager → audio
     *   cameraManager → camera
     *   systemPasteboard → pasteboard
     *   connection → connection
     *   geoLocationManager → geoLocationManager
     *
     * This is a last-resort heuristic when all type-based strategies fail.
     * It only adds candidates; the method name still needs to match a rule,
     * and the heuristic fallback in matchIndirectCall() will validate via
     * isMethodUniqueToNamespace() and ptaClassHasMethod().
     */
    static Set<String> inferNamespaceFromVariableName(Local base) {
        Set<String> candidates = new LinkedHashSet<>();
        if (base == null) return candidates;
        try {
            String varName = base.getName();
            if (varName == null || varName.isEmpty()) return candidates;
            String lower = varName.toLowerCase(Locale.ROOT);

            // Map of variable name substrings to namespace candidates.
            // Ordered from most specific to least specific.
            // Only include patterns that are strongly correlated with a specific namespace.
            String[][] namePatterns = {
                    // audio module
                    {"audiomanager", "audio"},
                    {"audiorenderer", "audio"},
                    {"audiocapturer", "audio"},
                    // camera module
                    {"cameramanager", "camera"},
                    // pasteboard module
                    {"systempasteboard", "pasteboard"},
                    {"pasteboardobj", "pasteboard"},
                    {"pasterecord", "pasteboard"},
                    // network module
                    {"netconnection", "connection"},
                    // telephony module
                    {"cellulardata", "telephony"},
                    // wifi module
                    {"wificonnection", "wifiManager"},
                    // location module
                    {"geolocationmanager", "geoLocationManager"},
                    // display module
                    {"defaultdisplay", "display"},
                    // bluetooth
                    {"bluetoothremote", "bluetooth"},
                    // sensor module
                    {"sensoragent", "sensor"},
                    // distributed device manager
                    {"devicemanager", "distributedDeviceManager"},
            };

            for (String[] pair : namePatterns) {
                if (lower.contains(pair[0])) {
                    candidates.add(pair[1]);
                }
            }
        } catch (Throwable ignored) {}
        return candidates;
    }

    /**
     * Extracts the method name from a call expression.
     * Handles both StaticCallExpr and InstanceCallExpr by getting the
     * function reference's name or the call expression's method name.
     */
    // Package-private: accessible by CaiResolver
    static String extractMethodNameFromCallExpr(
            com.huawei.hianalyzer.ir.value.expr.CallExpr callExpr) {
        try {
            // Try FunctionRef first — works for both static and instance calls
            var funcRef = callExpr.getFunctionRef();
            if (funcRef != null) {
                String name = funcRef.getName();
                if (name != null && !name.isEmpty()) {
                    // For compound names like "getAudioManager", extract the last segment
                    int lastDot = name.lastIndexOf('.');
                    return lastDot >= 0 ? name.substring(lastDot + 1) : name;
                }
            }
            // Fallback: use the call expression's string representation
            String exprStr = callExpr.toString();
            if (exprStr != null && !exprStr.contains("(")) {
                int lastDot = exprStr.lastIndexOf('.');
                return lastDot >= 0 ? exprStr.substring(lastDot + 1) : exprStr;
            }
        } catch (Throwable ignored) {}
        return null;
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

        // Check if ANY candidate is compatible.
        // Use canonical namespace comparison instead of overly broad prefix matching.
        // Prefix matching (e.g., "audiomanager".startsWith("audio")) was too permissive
        // and prevented detection of real contradictions.
        String ruleCanonical = getCanonicalNamespace(ruleNamespace.toLowerCase(Locale.ROOT));
        for (String candidate : candidates) {
            if (candidate == null || candidate.isEmpty()) continue;
            String candidateLower = candidate.toLowerCase(Locale.ROOT);
            // Direct match in compatible set
            if (compatibleLower.contains(candidateLower)) return false;
            // Canonical namespace match: check if the candidate's canonical form
            // matches any compatible namespace's canonical form
            String candidateCanonical = getCanonicalNamespace(candidateLower);
            if (candidateCanonical.equals(ruleCanonical)) return false;
            // Also check if candidate is an alias of any compatible namespace
            List<String> candidateAliases = PACKAGE_ALIASES.get(candidateLower);
            if (candidateAliases != null) {
                for (String cAlias : candidateAliases) {
                    if (compatibleLower.contains(cAlias.toLowerCase(Locale.ROOT))) return false;
                }
            }
        }
        // All candidates contradict
        return true;
    }

    /**
     * Checks if a method name uniquely identifies a single namespace among the given rules.
     * This is used as a heuristic fallback: if only one rule has this method name,
     * we can safely match by method name alone even without namespace confirmation.
     *
     * Rules with the same (namespace, method) pair are treated as duplicates —
     * they represent the same API under different systemPackage aliases
     * (e.g., @kit.AudioKit vs @ohos.multimedia.audio), so they count as one.
     */
    public static boolean isMethodUniqueToNamespace(String method, List<PreciseSensitiveApiScanner.PrivacyApiRuleWithPkg> indirectRules) {
        if (method == null || indirectRules == null) {
            return false;
        }
        // Check cache first (populated by precomputeMethodUniqueness)
        Boolean cached = methodUniqueCache.get(method);
        if (cached != null) return cached;
        // Use canonical namespace keys that collapse aliases.
        // Namespaces that are aliases of each other (e.g., SystemPasteboard vs pasteboard)
        // represent the same API module and should count as one.
        Set<String> seenCanonicalNamespaces = new HashSet<>();
        for (PreciseSensitiveApiScanner.PrivacyApiRuleWithPkg item : indirectRules) {
            String baseMethod = NamePathMatcher.stripMethodArguments(item.rule.method);
            if (method.equals(baseMethod)) {
                String ns = item.rule.namespace != null ? item.rule.namespace.toLowerCase(Locale.ROOT) : "";
                // Collapse namespace using PACKAGE_ALIASES: map to a canonical representative
                String canonicalNs = getCanonicalNamespace(ns);
                String key = canonicalNs + "|" + baseMethod.toLowerCase(Locale.ROOT);
                if (!seenCanonicalNamespaces.contains(key)) {
                    seenCanonicalNamespaces.add(key);
                    if (seenCanonicalNamespaces.size() > 1) {
                        return false;
                    }
                }
            }
        }
        return seenCanonicalNamespaces.size() == 1;
    }

    /** Cache for getCanonicalNamespace results. */
    private static final Map<String, String> canonicalNamespaceCache = new java.util.concurrent.ConcurrentHashMap<>();

    /** Cache for isMethodUniqueToNamespace results. */
    private static final Map<String, Boolean> methodUniqueCache = new java.util.concurrent.ConcurrentHashMap<>();

    /**
     * Pre-computes method uniqueness cache from the given indirect rules.
     * Call this once at the start of analysis to avoid repeated O(n) scans.
     */
    public static void precomputeMethodUniqueness(List<PreciseSensitiveApiScanner.PrivacyApiRuleWithPkg> indirectRules) {
        methodUniqueCache.clear();
        Map<String, Set<String>> methodToCanonicalNs = new LinkedHashMap<>();
        for (var item : indirectRules) {
            String baseMethod = NamePathMatcher.stripMethodArguments(item.rule.method);
            if (baseMethod == null || baseMethod.isEmpty()) continue;
            String ns = item.rule.namespace != null ? item.rule.namespace.toLowerCase(Locale.ROOT) : "";
            String canonicalNs = getCanonicalNamespace(ns);
            String key = canonicalNs + "|" + baseMethod.toLowerCase(Locale.ROOT);
            methodToCanonicalNs.computeIfAbsent(baseMethod, k -> new LinkedHashSet<>())
                    .add(key);
        }
        for (var entry : methodToCanonicalNs.entrySet()) {
            methodUniqueCache.put(entry.getKey(), entry.getValue().size() == 1);
        }
    }

    /**
     * Returns a canonical namespace key that collapses aliases.
     * If the namespace is an alias of another (via PACKAGE_ALIASES),
     * returns the shortest form among the namespace and its aliases.
     * This ensures that SystemPasteboard and pasteboard both map to the same key.
     * Results are cached for performance.
     */
    // Package-private: accessible by CaiResolver
    static String getCanonicalNamespace(String nsLower) {
        if (nsLower == null || nsLower.isEmpty()) return nsLower;
        String cached = canonicalNamespaceCache.get(nsLower);
        if (cached != null) return cached;
        // Check if this namespace has aliases — use the shortest as canonical
        List<String> candidates = new ArrayList<>();
        candidates.add(nsLower);
        // Check both directions: nsLower as key and nsLower as alias value
        List<String> aliases = PACKAGE_ALIASES.get(nsLower);
        if (aliases != null) {
            for (String alias : aliases) {
                candidates.add(alias.toLowerCase(Locale.ROOT));
            }
        }
        // Also check if nsLower appears as a value in any PACKAGE_ALIASES entry
        for (Map.Entry<String, List<String>> entry : PACKAGE_ALIASES.entrySet()) {
            for (String alias : entry.getValue()) {
                if (alias.toLowerCase(Locale.ROOT).equals(nsLower)) {
                    candidates.add(entry.getKey().toLowerCase(Locale.ROOT));
                    break;
                }
            }
        }
        // Return the shortest candidate as canonical
        candidates.sort((a, b) -> a.length() - b.length());
        String result = candidates.get(0);
        canonicalNamespaceCache.put(nsLower, result);
        return result;
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
