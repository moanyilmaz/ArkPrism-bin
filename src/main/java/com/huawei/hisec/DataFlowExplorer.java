package com.huawei.hisec;

import com.huawei.hianalyzer.analysis.Stage;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.base.HiFunction;
import com.huawei.hianalyzer.analysis.graph.callgraph.CallGraph;
import com.huawei.hianalyzer.analysis.graph.icfg.ICFG;
import com.huawei.hianalyzer.dataflow.ifds.analysis.TaintAnalysis;
import com.huawei.hianalyzer.ir.stmt.CallStmt;
import com.huawei.hianalyzer.ir.stmt.Stmt;

import java.util.*;

/**
 * DataFlowExplorer performs inter-procedural data flow analysis to detect
 * privacy-sensitive data leakage patterns.
 *
 * Current Strategy:
 * 1. Enable IFDS-based taint analysis when available
 * 2. Run analysis per-source to avoid false source-sink associations
 * 3. Default to empty dataSinks on any internal tool failure
 * 4. When Huawei's IFDS is fixed, simply set ENABLE_IFDS to true
 */
public class DataFlowExplorer {

    /**
     * Enable IFDS-based taint analysis.
     * Set to false if encountering internal tool failures.
     */
    private static final boolean ENABLE_IFDS = true;

    /**
     * Run IFDS analysis per source (one source at a time).
     * This avoids the issue where TaintAnalysis.solveAndGetResults() returns
     * global hit sinks rather than source->sink mappings.
     *
     * Set to false for better performance when source->sink mapping is not needed.
     */
    private static final boolean RUN_PER_SOURCE = true;

    /**
     * PrivacyCatalog: auto-generated from privacy_apis.json at first use.
     * Used for source/sink detection and def-use analysis.
     */
    private static volatile PrivacyCatalog catalog;

    private static void ensureCatalog(String jsonPath) {
        if (catalog == null) {
            synchronized (DataFlowExplorer.class) {
                if (catalog == null) {
                    catalog = new PrivacyCatalog(jsonPath);
                }
            }
        }
    }

    /**
     * Def-use analysis: checks if a statement's definition is actually used later.
     * Used to detect dead-code constant assignments.
     */
    public static boolean isValueUsed(Stmt stmt) {
        if (catalog != null) {
            return catalog.isValueUsed(stmt);
        }
        return true;
    }

    // Network exfiltration sinks
    private static final Set<String> NETWORK_SINKS = new HashSet<>(Arrays.asList(
            "@system:@ohos:net.http.request",
            "@system:@ohos:net.http.requestInStream",
            "@system:@ohos:net.http.createHttp",
            "@system:@ohos:net.socket.constructTCPSocketInstance",
            "@system:@ohos:net.socket.constructUDPSocketInstance",
            "@system:@ohos:net.socket.constructTLSSocketInstance",
            "@system:@ohos:request.uploadFile",
            "@system:@ohos:request.downloadFile",
            "@system:@ohos:web.webview.loadUrl",
            "@system:@ohos:web.webview.runJavaScript",
            "@system:@ohos:web.webview.fetchCookie",
            "@system:@ohos:web.webview.saveCookieAsync",
            "@system:@ohos:web.webview.configCookie"
    ));

    // Local storage / persistence sinks
    private static final Set<String> STORAGE_SINKS = new HashSet<>(Arrays.asList(
            "@system:@ohos:file.fs.open",
            "@system:@ohos:file.fs.write",
            "@system:@ohos:file.fs.read",
            "@system:@ohos:file.fs.stat",
            "@system:@ohos:file.fs.listFile",
            "@system:@ohos:file.fs.access",
            "@system:@ohos:data.preferences.put",
            "@system:@ohos:data.preferences.flushSync",
            "@system:@ohos:data.preferences.deletePreferences",
            "@system:@ohos:data.preferences.getPreferences",
            "@system:@ohos:data.preferences.getPreferencesSync",
            "@system:@ohos:data.relationalStore.getRdbStore",
            "@system:@ohos:data.relationalStore.deleteRdbStore",
            "@system:@ohos:data.distributedKVStore.createKVManager",
            "@system:@ohos:data.distributedKVStore.getKVStore",
            "@system:@ohos:settings.setValue",
            "@system:@ohos:settings.getValue",
            "@system:@ohos:settings.getValueSync"
    ));

    // Clipboard / user data leakage sinks
    private static final Set<String> CLIPBOARD_SINKS = new HashSet<>(Arrays.asList(
            "@system:@ohos:pasteboard.getSystemPasteboard",
            "@system:@ohos:pasteboard.getData",
            "@system:@ohos:pasteboard.getPasteData",
            "@system:@ohos:pasteboard.getPrimaryText"
    ));

    // Logging / analytics sinks
    private static final Set<String> LOGGING_SINKS = new HashSet<>(Arrays.asList(
            "console.log",
            "console.info",
            "console.warn",
            "console.error",
            "@system:@ohos:hiAppEvent.write"
    ));

    // Media file creation sinks
    private static final Set<String> MEDIA_SINKS = new HashSet<>(Arrays.asList(
            "@system:@ohos:file.photoAccessHelper.createAsset"
    ));

    /**
     * Source API keyword patterns: APIs that READ privacy-sensitive data.
     * Uses substring matching for taint analysis.
     */
    private static final Set<String> SOURCE_KEYWORD_PATTERNS = new HashSet<>(Arrays.asList(
            // Location - reading location data
            "geoLocationManager.getCurrentLocation",
            "geoLocationManager.getLastLocation",
            "geoLocationManager.getAddressesFromLocation",
            "geoLocationManager.getCountryCode",
            "geoLocationManager.on",
            "geoLocationManager.isLocationEnabled",
            "geoLocationManager.enableLocation",
            "geoLocationManager.disableLocation",
            // Device identity
            "deviceInfo.brand",
            "deviceInfo.productModel",
            "deviceInfo.deviceType",
            "deviceInfo.osFullName",
            "deviceInfo.osVersion",
            "deviceInfo.sdkApiVersion",
            "deviceInfo.distributionOSName",
            "deviceInfo.distributionOSVersion",
            "deviceInfo.displayVersion",
            "wifiManager.getDeviceMacAddress",
            "wifiManager.getIpInfo",
            "wifiManager.getScanInfoList",
            "wifiManager.getLinkedInfo",
            "identifier.oaid",
            "telephony.getSimOperatorNumeric",
            "telephony.getSimSpn",
            "telephony.getNetworkState",
            "telephony.getSignalInformation",
            // Contacts
            "contact.selectContacts",
            "contact.queryContacts",
            "contact.queryContact",
            "contact.queryContactsByPhoneNumber",
            "contact.queryContactsByEmail",
            // Calendar
            "calendarManager.getCalendar",
            "calendarManager.getAllCalendars",
            "calendarManager.getEvents",
            // Media access
            "photoAccessHelper.getPhotoAccessHelper",
            "photoAccessHelper.getAssets",
            "photoAccessHelper.getAlbums",
            "photoAccessHelper.select",
            // Audio recording
            "multimedia.audio.createAudioCapturer",
            "audio.createAudioCapturer",
            // Camera
            "multimedia.camera.getCameraManager",
            "camera.getCameraManager",
            "camera.createCaptureSession",
            "camera.createPhotoOutput",
            // SMS
            "telephony.sms.getDefaultSmsSimId",
            "telephony.sms.getDefaultSmsSlotId",
            "telephony.sms.sendMessage",
            // Account info
            "account.osAccount.getOsAccountLocalId",
            "account.appAccount.getAllAccounts",
            "account.distributedAccount",
            // Sensors
            "sensor.on",
            "sensor.once",
            "sensor.getSensorList",
            // Bundle info
            "bundleManager.getBundleInfo",
            "bundleManager.getApplicationInfo",
            // App info
            "appManager.getProcessInfo",
            "appManager.getRunningAppProcessInfo",
            // Bluetooth
            "bluetooth.connection.getPairedDevices",
            "bluetooth.connection.getRemoteDeviceName",
            // Clipboard
            "pasteboard.getSystemPasteboard",
            "pasteboard.getData",
            "pasteboard.getPasteData",
            "pasteboard.getPrimaryText"
    ));

    /**
     * Combined sink APIs by category.
     */
    public static final Set<String> DEFAULT_SINK_APIS = new HashSet<>();
    static {
        DEFAULT_SINK_APIS.addAll(NETWORK_SINKS);
        DEFAULT_SINK_APIS.addAll(STORAGE_SINKS);
        DEFAULT_SINK_APIS.addAll(CLIPBOARD_SINKS);
        DEFAULT_SINK_APIS.addAll(LOGGING_SINKS);
        DEFAULT_SINK_APIS.addAll(MEDIA_SINKS);
    }

    /**
     * Performs forward data flow analysis to detect privacy data leakage.
     *
     * @param hiFile      Parsed HiFile containing function bodies
     * @param cg          Call graph for inter-procedural analysis
     * @param sourceStmts Set of source statements (sensitive API calls)
     * @param jsonPath    Path to privacy_apis.json
     * @return Map from source Stmt to list of sink CallStmt
     */
    public static Map<Stmt, List<CallStmt>> findDataSinks(
            HiFile hiFile,
            CallGraph cg,
            Set<Stmt> sourceStmts,
            String jsonPath
    ) {
        Map<Stmt, List<CallStmt>> sourceToSinksMap = new LinkedHashMap<>();

        if (hiFile == null || cg == null || sourceStmts == null || sourceStmts.isEmpty()) {
            return sourceToSinksMap;
        }

        if (jsonPath != null && !jsonPath.isBlank()) {
            ensureCatalog(jsonPath);
        }

        Set<CallStmt> ifdsSources = collectValidSources(hiFile, sourceStmts);
        if (ifdsSources.isEmpty()) {
            return sourceToSinksMap;
        }

        Set<CallStmt> ifdsSinks = collectCandidateSinks(hiFile);
        if (ifdsSinks.isEmpty()) {
            return sourceToSinksMap;
        }

        Logger.log("[DataFlow] candidate sources=" + ifdsSources.size()
                + ", candidate sinks=" + ifdsSinks.size());

        if (!ENABLE_IFDS) {
            Logger.log("[DataFlow] IFDS disabled; dataSinks will remain empty.");
            return sourceToSinksMap;
        }

        if (RUN_PER_SOURCE) {
            return runIfdsPerSource(hiFile, cg, ifdsSources, ifdsSinks);
        } else {
            return runIfdsGlobal(hiFile, cg, ifdsSources, ifdsSinks);
        }
    }

    /**
     * Runs IFDS analysis with all sources together (global mode).
     * Faster than per-source mode, but doesn't provide source->sink mapping.
     */
    private static Map<Stmt, List<CallStmt>> runIfdsGlobal(
            HiFile hiFile,
            CallGraph cg,
            Set<CallStmt> ifdsSources,
            Set<CallStmt> ifdsSinks
    ) {
        Map<Stmt, List<CallStmt>> result = new LinkedHashMap<>();

        ICFG icfg;
        try {
            icfg = Stage.createICFG(hiFile, cg);
            Logger.log("[DataFlow] ICFG created. nodes=" + safeSize(icfg.getNodes())
                    + ", edges=" + safeSize(icfg.getEdges()));
        } catch (Throwable t) {
            Logger.error("[DataFlow] Stage.createICFG failed: " + safeMessage(t));
            return result;
        }

        try {
            Logger.log("[DataFlow] Running global IFDS with " + ifdsSources.size()
                    + " sources and " + ifdsSinks.size() + " sinks");

            TaintAnalysis taintAnalysis = TaintAnalysis.createTaintAnalysisByStmt(
                    ifdsSources,
                    ifdsSinks
            );

            Set<CallStmt> hitSinks = taintAnalysis.solveAndGetResults(icfg);

            if (hitSinks != null && !hitSinks.isEmpty()) {
                Logger.log("[DataFlow] HIT! Global analysis found " + hitSinks.size() + " polluted sinks");
                // Put all hit sinks under all sources (no precise mapping)
                for (CallStmt source : ifdsSources) {
                    result.put(source, new ArrayList<>(hitSinks));
                }
            } else {
                Logger.log("[DataFlow] no paths found from any source to any sink");
            }
        } catch (Throwable t) {
            Logger.error("[DataFlow] global IFDS failed: " + safeMessage(t));
        }

        return result;
    }

    /**
     * Runs IFDS analysis for each source independently.
     * This approach avoids false associations when a sink is reachable from
     * multiple sources via different paths.
     */
    private static Map<Stmt, List<CallStmt>> runIfdsPerSource(
            HiFile hiFile,
            CallGraph cg,
            Set<CallStmt> ifdsSources,
            Set<CallStmt> ifdsSinks
    ) {
        Map<Stmt, List<CallStmt>> result = new LinkedHashMap<>();

        ICFG icfg;
        try {
            icfg = Stage.createICFG(hiFile, cg);
            Logger.log("[DataFlow] ICFG created. nodes=" + safeSize(icfg.getNodes())
                    + ", edges=" + safeSize(icfg.getEdges()));
        } catch (Throwable t) {
            Logger.error("[DataFlow] Stage.createICFG failed: " + safeMessage(t));
            return result;
        }

        int index = 0;
        for (CallStmt source : ifdsSources) {
            index++;

            Set<CallStmt> singleSource = new HashSet<>();
            singleSource.add(source);

            String sourceApi = safeGetFullApiName(hiFile, source);
            String sourceFuncName = getFunctionName(source);

            try {
                Logger.log("[DataFlow] IFDS solving source "
                        + index + "/" + ifdsSources.size()
                        + " [" + nvl(sourceApi, shortStmt(source)) + "]"
                        + " in " + sourceFuncName);

                // Verify source function has valid body
                HiFunction sourceFunc = getHiFunctionSafe(source);
                if (sourceFunc == null || !hasValidBody(sourceFunc)) {
                    Logger.log("[DataFlow]   skipped: source function has null body");
                    continue;
                }

                Logger.log("[DataFlow]   total candidate sinks: " + ifdsSinks.size());

                TaintAnalysis taintAnalysis = TaintAnalysis.createTaintAnalysisByStmt(
                        singleSource,
                        ifdsSinks
                );

                Set<CallStmt> hitSinks = taintAnalysis.solveAndGetResults(icfg);

                if (hitSinks != null && !hitSinks.isEmpty()) {
                    result.put(source, new ArrayList<>(hitSinks));
                    Logger.log("[DataFlow]   HIT! source hit sinks=" + hitSinks.size());
                } else {
                    Logger.log("[DataFlow]   no paths found from source to any sink");
                }

            } catch (Throwable t) {
                Logger.error("[DataFlow]   skipped due to exception in ICFG solving: " + safeMessage(t));
            }
        }

        return result;
    }

    /**
     * Collects valid source statements from the given set.
     * A valid source must:
     * - Be a CallStmt
     * - Have a function with non-null body
     * - Be a known SOURCE API (data collection, not data exfiltration)
     */
    private static Set<CallStmt> collectValidSources(HiFile hiFile, Set<Stmt> sourceStmts) {
        Set<CallStmt> result = new LinkedHashSet<>();

        for (Stmt stmt : sourceStmts) {
            if (!(stmt instanceof CallStmt)) {
                continue;
            }

            CallStmt callStmt = (CallStmt) stmt;
            HiFunction sourceFunc = getHiFunctionSafe(callStmt);

            if (sourceFunc == null || !hasValidBody(sourceFunc)) {
                continue;
            }

            String apiName = safeGetFullApiName(hiFile, callStmt);
            boolean isSource = catalog != null
                    ? catalog.isSourceApi(hiFile, callStmt)
                    : (apiName != null && containsAnyPattern(apiName, SOURCE_KEYWORD_PATTERNS));
            if (!isSource) {
                continue;
            }

            result.add(callStmt);
        }

        return result;
    }

    /**
     * Collects candidate sink statements from all functions with valid bodies.
     */
    private static Set<CallStmt> collectCandidateSinks(HiFile hiFile) {
        Set<CallStmt> result = new LinkedHashSet<>();

        for (HiFunction function : safeHiFunctions(hiFile)) {
            if (!hasValidBody(function)) {
                continue;
            }

            for (Stmt stmt : safeStmts(function)) {
                if (!(stmt instanceof CallStmt)) {
                    continue;
                }

                CallStmt callStmt = (CallStmt) stmt;
                String apiName = safeGetFullApiName(hiFile, callStmt);

                if (apiName != null && containsAnyPattern(apiName, DEFAULT_SINK_APIS)) {
                    // Exclude source APIs from sink set
                    if (isSourceApi(apiName)) {
                        continue;
                    }
                    result.add(callStmt);
                }
            }
        }

        return result;
    }

    /**
     * Checks if the owner function of a CallStmt has a valid body.
     */
    private static boolean hasValidOwnerFunction(CallStmt callStmt) {
        if (callStmt == null) {
            return false;
        }

        try {
            HiFunction func = callStmt.getHiFunction();
            if (func == null || !hasValidBody(func)) {
                return false;
            }
            return true;
        } catch (Throwable t) {
            Logger.error("[-] DataFlow hasValidOwnerFunction exception: " + safeMessage(t));
            return false;
        }
    }

    /**
     * Checks if a HiFunction has a valid (non-null, non-empty) body.
     */
    private static boolean hasValidBody(HiFunction function) {
        if (function == null) {
            return false;
        }

        try {
            return function.getBody() != null
                    && function.getBody().getStmts() != null
                    && !function.getBody().getStmts().isEmpty();
        } catch (Throwable t) {
            Logger.error("[-] DataFlow hasValidBody exception: " + safeMessage(t));
            return false;
        }
    }

    private static Collection<HiFunction> safeHiFunctions(HiFile hiFile) {
        if (hiFile == null) {
            return Collections.emptyList();
        }

        try {
            Collection<HiFunction> functions = hiFile.getHiFunctions();
            return functions == null ? Collections.emptyList() : functions;
        } catch (Throwable t) {
            return Collections.emptyList();
        }
    }

    private static List<Stmt> safeStmts(HiFunction function) {
        if (!hasValidBody(function)) {
            return Collections.emptyList();
        }

        try {
            List<Stmt> stmts = function.getBody().getStmts();
            return stmts == null ? Collections.emptyList() : stmts;
        } catch (Throwable t) {
            return Collections.emptyList();
        }
    }

    private static HiFunction getHiFunctionSafe(Stmt stmt) {
        try {
            if (stmt instanceof CallStmt) {
                return ((CallStmt) stmt).getHiFunction();
            }
            return null;
        } catch (Throwable t) {
            return null;
        }
    }

    private static String getFunctionName(Stmt stmt) {
        HiFunction func = getHiFunctionSafe(stmt);
        return func != null ? safeFunctionName(func) : "<unknown>";
    }

    private static String safeGetFullApiName(HiFile hiFile, CallStmt callStmt) {
        try {
            return hiFile.getFullApiNameByStmt(callStmt);
        } catch (Throwable t) {
            return null;
        }
    }

    private static String safeFunctionName(HiFunction func) {
        if (func == null) {
            return "<null>";
        }

        try {
            String name = func.getName();
            return name == null ? "<unnamed>" : name;
        } catch (Throwable t) {
            return "<name-error>";
        }
    }

    /**
     * Checks if text contains any of the given patterns.
     * Uses suffix matching with "." separator.
     */
    private static boolean containsAnyPattern(String text, Set<String> patterns) {
        if (text == null || patterns == null || patterns.isEmpty()) {
            return false;
        }

        for (String pattern : patterns) {
            if (pattern != null && !pattern.isEmpty() && matchesPattern(text, pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Pattern matching for API names.
     * Strips "@system:@ohos:" prefix and does suffix match with "." separator.
     */
    private static boolean matchesPattern(String apiName, String pattern) {
        if (apiName == null || pattern == null) {
            return false;
        }

        String strippedApi = apiName;
        String strippedPattern = pattern;

        if (strippedApi.startsWith("@system:@ohos:")) {
            strippedApi = strippedApi.substring("@system:@ohos:".length());
        }
        if (strippedPattern.startsWith("@system:@ohos:")) {
            strippedPattern = strippedPattern.substring("@system:@ohos:".length());
        }

        // Exact match
        if (strippedApi.equals(strippedPattern)) {
            return true;
        }

        // Suffix match with "." separator
        if (strippedApi.endsWith(strippedPattern)) {
            int sepPos = strippedApi.length() - strippedPattern.length() - 1;
            if (sepPos >= 0 && strippedApi.charAt(sepPos) == '.') {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks if an API is a source API.
     */
    private static boolean isSourceApi(String apiName) {
        if (apiName == null) {
            return false;
        }
        for (String pattern : SOURCE_KEYWORD_PATTERNS) {
            if (matchesPattern(apiName, "@system:@ohos:" + pattern)) {
                return true;
            }
            if (matchesPattern(apiName, pattern)) {
                return true;
            }
        }
        return false;
    }

    private static int safeSize(Collection<?> collection) {
        return collection == null ? -1 : collection.size();
    }

    private static String safeMessage(Throwable throwable) {
        if (throwable == null) {
            return "unknown error";
        }

        String msg = throwable.getMessage();
        if (msg == null || msg.isBlank()) {
            return throwable.getClass().getName();
        }

        return throwable.getClass().getName() + ": " + msg;
    }

    private static String nvl(String value, String defaultValue) {
        return value != null ? value : defaultValue;
    }

    private static String shortStmt(Stmt stmt) {
        if (stmt == null) {
            return "<null>";
        }

        try {
            String s = String.valueOf(stmt);
            return s.length() > 200 ? s.substring(0, 200) + "..." : s;
        } catch (Throwable t) {
            return "<stmt-toString-failed>";
        }
    }
}