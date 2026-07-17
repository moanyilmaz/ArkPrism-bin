package com.huawei.hisec;

import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.base.HiFunction;
import com.huawei.hianalyzer.ir.stmt.CallStmt;
import com.huawei.hianalyzer.ir.stmt.Stmt;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Shared utility methods for the ArkPrism scanner pipeline.
 *
 * Includes:
 * - Report building (source snippets, data sinks, semantic context)
 * - Type/category inference (profiling category, risk, entry method type, etc.)
 * - Safe accessors (HiFunction, method body, stmt index)
 * - String normalization and formatting
 */
public class ScannerUtils {

    // ======================================================
    // Report building
    // ======================================================

    public static UnifiedPrivacyReport.SourceSnippet buildSourceSnippet(HiFunction func, String fileName) {
        UnifiedPrivacyReport.SourceSnippet snippet = new UnifiedPrivacyReport.SourceSnippet();
        snippet.method = safeFunctionName(func);
        snippet.file = fileName;
        snippet.startLine = -1;
        snippet.endLine = -1;
        snippet.code = String.join("\n", safeGetMethodBody(func));
        snippet.originalCode = null;
        return snippet;
    }

    public static List<UnifiedPrivacyReport.DataSink> convertDataSinks(
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

    public static UnifiedPrivacyReport.SemanticContext buildSemanticContext(
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

    // ======================================================
    // Type/category inference
    // ======================================================

    static String inferSinkType(String sinkApi) {
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

    static String normalizeApiPackage(String systemPackage) {
        if (systemPackage == null || systemPackage.isBlank()) {
            return "UnknownPackage";
        }
        return systemPackage;
    }

    static String inferArkTsProfilingCategory(String namespace, String method, String systemPackage) {
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

    static String inferArkTsRisk(String profilingCategory, String permission) {
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

    static String inferEntryMethodType(HiFunction func) {
        String name = safeFunctionName(func);
        String lowerName = name.toLowerCase(Locale.ROOT);

        // HarmonyOS ArkUI Component Lifecycle Methods
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

        // HarmonyOS Ability Lifecycle Methods
        if (lowerName.contains("onabilitycreate") || lowerName.contains("onabilitydestroy") ||
            lowerName.contains("onabilityforeground") || lowerName.contains("onabilitybackground") ||
            lowerName.contains("onwindowstagecreate") || lowerName.contains("onwindowstagedestroy") ||
            lowerName.contains("oncontinue") || lowerName.contains("onnewwant") ||
            lowerName.contains("ondump") || lowerName.contains("onrequest")) {
            return "ability_lifecycle";
        }

        // HarmonyOS ArkUI Component Constructors
        if (name.endsWith("Component") || name.endsWith("Page") ||
            name.endsWith("View") || name.endsWith("Builder") ||
            name.endsWith("Element") || name.endsWith("Item") ||
            lowerName.contains("listcomponent") || lowerName.contains("gridcomponent") ||
            lowerName.contains("buttoncomponent") || lowerName.contains("textcomponent") ||
            lowerName.contains("imagecomponent") || lowerName.contains("webcomponent") ||
            lowerName.contains("inputcomponent") || lowerName.contains("switchcomponent") ||
            lowerName.contains("slidercomponent") || lowerName.contains("checkboxcomponent") ||
            lowerName.contains("radiocomponent") || lowerName.contains("togglecomponent") ||
            lowerName.contains("dialogcomponent") || lowerName.contains("popupcomponent") ||
            lowerName.contains("tabcomponent") || lowerName.contains("navcomponent") ||
            (lowerName.contains("page") && !lowerName.contains("onpage"))) {
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

    static String inferEntryMethodTypeByName(String functionName) {
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

    static String inferCallType(HiFunction caller, HiFunction callee) {
        String callerName = safeFunctionName(caller).toLowerCase(Locale.ROOT);
        String calleeName = safeFunctionName(callee).toLowerCase(Locale.ROOT);

        if (callerName.contains(".build") || callerName.contains("aboutToAppear")) {
            if (calleeName.contains("onclick") || calleeName.contains("%am") ||
                calleeName.contains("handler") || calleeName.contains("callback")) {
                return "lifecycle_trigger";
            }
        }

        if (callerName.contains("onclick") || callerName.contains("%o_click") ||
            callerName.contains("ontouch") || callerName.contains("onsubmit")) {
            return "event_handler_call";
        }

        if (callerName.contains("callback") || callerName.contains("%resolve") ||
            callerName.contains("%reject") || callerName.contains("then(")) {
            return "async_callback_call";
        }

        if (callerName.contains("onInit") || callerName.contains("onCreate") ||
            callerName.contains("onReady")) {
            return "lifecycle_init";
        }

        return "direct";
    }

    static String inferPageName(String fileName) {
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

    static String inferComponentClass(String functionName) {
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

    static String simplifyFunctionName(String name) {
        if (name == null) {
            return "Unknown";
        }

        String s = name;

        // Handle HarmonyOS internal function IDs like #65045#
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
    // Safe accessors
    // ======================================================

    static List<String> safeGetMethodBody(HiFunction func) {
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

    static HiFunction safeGetHiFunction(Stmt stmt) {
        try {
            return stmt == null ? null : stmt.getHiFunction();
        } catch (Throwable t) {
            return null;
        }
    }

    static String safeFunctionName(HiFunction func) {
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

    static int safeStmtIndex(Stmt stmt) {
        try {
            return stmt == null ? -1 : stmt.getIndex();
        } catch (Throwable t) {
            return -1;
        }
    }

    // ======================================================
    // String utilities
    // ======================================================

    static boolean isSsaPhiNode(String stmtText) {
        if (stmtText == null || stmtText.isEmpty()) {
            return false;
        }

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
            if (rhs.startsWith(lhs + ".")) {
                return true;
            }
            return false;
        }

        String inside = rhs.substring("VirtualCall: ".length()).trim();
        if (inside.startsWith(lhs + ".")) {
            return true;
        }

        return false;
    }

    static String safe(Object obj) {
        if (obj == null) {
            return null;
        }

        try {
            return String.valueOf(obj);
        } catch (Throwable t) {
            return null;
        }
    }

    static String safePath(java.io.File file) {
        if (file == null) {
            return "<null>";
        }

        try {
            return file.getAbsolutePath();
        } catch (Throwable t) {
            return String.valueOf(file);
        }
    }

    static String normalizeFullName(String s) {
        return s == null ? null : s.trim();
    }

    static boolean endsWithDotted(String full, String suffix) {
        return full != null
                && suffix != null
                && (full.equals(suffix) || full.endsWith("." + suffix));
    }

    static List<String> extractArgsFromStmt(String stmtText) {
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

    static String extractApiTailFromStmt(String stmtText) {
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
}
