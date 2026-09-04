package com.huawei.hisec;

import java.util.*;

/**
 * Name and path matching utilities for resolved API names.
 *
 * Handles parsing of HiAnalyzer resolved names (e.g., "@ohos.net.http.HttpRequest.request"),
 * method-path matching, namespace-position matching, and argument extraction.
 */
public class NamePathMatcher {

    // ======================================================
    // Resolved name parsing
    // ======================================================

    /**
     * Parses a resolved API name into its components.
     *
     * Example inputs:
     *   "@system:@ohos:geoLocationManager.getCurrentLocation"
     *   "@bundle:com.example.app@ohos:net.http.request"
     *   "@import:com.legado.app.entry.ets.pages.deviceid.#Foreign: unknown distributedDeviceManager"
     *
     * @param fullName The full resolved API name from HiAnalyzer
     * @return ResolvedNameInfo with parsed components
     */
    public static PreciseSensitiveApiScanner.ResolvedNameInfo parseResolvedName(String fullName) {
        PreciseSensitiveApiScanner.ResolvedNameInfo info = new PreciseSensitiveApiScanner.ResolvedNameInfo();
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

    /**
     * Checks if a resolved name is accepted based on its source prefix.
     * Filters out @unknown and @internal prefixes, and optionally restricts
     * to @system only when SYSTEM_ONLY_MODE is enabled.
     */
    public static boolean isAcceptedResolvedName(PreciseSensitiveApiScanner.ResolvedNameInfo info) {
        if (info == null || !info.valid || info.sourcePrefix == null) {
            return false;
        }

        if ("@unknown".equals(info.sourcePrefix)
                || "@internal".equals(info.sourcePrefix)) {
            return false;
        }

        // @bundle names may resolve to system APIs if the body contains @ohos: namespace.
        // Also accept @bundle names where the body doesn't contain @ohos: — these are
        // calls resolved from the application's own code (e.g., getSupportedCameras
        // resolved as @bundle:com.legado...camera.#GLOBAL:unknown getSupportedCameras(unknown)).
        // Such calls may still be privacy-sensitive API calls that need detection.
        if ("@bundle".equals(info.sourcePrefix)) {
            return true;
        }

        // SYSTEM_ONLY_MODE is false in the scanner, so accept both @system and @import
        return "@system".equals(info.sourcePrefix) || "@import".equals(info.sourcePrefix);
    }

    // ======================================================
    // Token matching
    // ======================================================

    public static boolean tokenListContains(List<String> tokens, String expected) {
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

    public static String getSourcePrefix(String fullName) {
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
     * Strict namespace matching: namespace must be the token immediately before method.
     * Prevents false matches like "foo.deviceInfo.bar.productModel" for namespace "deviceInfo".
     */
    public static boolean namespaceMustBePredecessor(List<String> pathTokens, String namespace) {
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
     * Strips parenthesized arguments from a method name.
     * Handles source-level API patterns like:
     *   "on('SensorId.ACCELEROMETER')" → "on"
     *   "once('SensorId.ACCELEROMETER')" → "once"
     */
    public static String stripMethodArguments(String method) {
        if (method == null || method.isEmpty()) {
            return method;
        }
        int parenIndex = method.indexOf('(');
        if (parenIndex > 0) {
            return method.substring(0, parenIndex).trim();
        }
        return method;
    }

    /**
     * Checks whether a rule's method name matches the path tokens of a resolved API name.
     *
     * Handles both simple method names (e.g., "uploadFile") and compound/dotted
     * method names (e.g., "agent.create") that arise when the source-level API
     * uses a sub-namespace + method pattern.
     */
    public static boolean methodMatchesPath(PreciseSensitiveApiScanner.ResolvedNameInfo info, String baseMethod) {
        if (baseMethod == null || baseMethod.isEmpty() || !info.valid) {
            return false;
        }

        // Simple case: no dots — exact match on lastToken
        if (!baseMethod.contains(".")) {
            return Objects.equals(baseMethod, info.lastToken);
        }

        // Dotted method: split into tokens and match suffix of pathTokens.
        String[] methodTokens = baseMethod.split("\\.");
        if (methodTokens.length == 0) {
            return false;
        }

        if (info.pathTokens == null || info.pathTokens.size() < methodTokens.length) {
            return false;
        }

        // Check that the last methodTokens.length tokens of pathTokens match
        int offset = info.pathTokens.size() - methodTokens.length;
        for (int i = 0; i < methodTokens.length; i++) {
            if (!methodTokens[i].equals(info.pathTokens.get(offset + i))) {
                return false;
            }
        }

        return true;
    }

    /**
     * Namespace matching that accounts for multi-token (dotted) method names
     * and package aliases.
     *
     * For simple methods: namespace must be the immediate predecessor of the method
     * token in pathTokens.
     *
     * For dotted methods like "agent.create" with namespace="request":
     *   pathTokens = [request, agent, create]
     *   The namespace "request" must appear immediately before the first method token "agent".
     *
     * Additionally, if the rule's namespace has aliases (e.g., "@ohos.geoLocationManager"
     * also matches "@kit.LocationKit"), we accept any alias at the namespace position.
     */
    public static boolean namespaceMatchesForMethod(List<String> pathTokens, String baseMethod, String namespace) {
        if (pathTokens == null || namespace == null || baseMethod == null) {
            return false;
        }

        int methodTokenCount = baseMethod.contains(".") ? baseMethod.split("\\.").length : 1;

        // Reviewed module-level functions have no receiver namespace. Accept
        // them only when the resolved path also contains no predecessor token.
        if (namespace.isEmpty()) {
            return pathTokens.size() == methodTokenCount;
        }

        int namespaceIndex = pathTokens.size() - methodTokenCount - 1;

        if (namespaceIndex < 0) {
            return false;
        }

        String actualNs = pathTokens.get(namespaceIndex);

        // Direct match (case-insensitive to handle "Connection" vs "connection")
        if (namespace.equalsIgnoreCase(actualNs)) {
            return true;
        }

        // Alias match
        for (String alias : NamespaceResolver.getRulePackagesForImport(namespace)) {
            if (alias.equalsIgnoreCase(actualNs)) {
                return true;
            }
            // Also check if the last segment of the alias matches
            int dot = alias.lastIndexOf('.');
            if (dot > 0 && alias.substring(dot + 1).equalsIgnoreCase(actualNs)) {
                return true;
            }
        }
        return false;
    }

    // ======================================================
    // Argument extraction
    // ======================================================

    /**
     * Extracts the argument pattern from a parenthesized method name.
     * Handles patterns like:
     *   "on('SensorId.ACCELEROMETER')" → "SensorId.ACCELEROMETER"
     *   "on('locationChange')" → "locationChange"
     */
    public static String extractMethodArgument(String method) {
        if (method == null || method.isEmpty()) {
            return null;
        }
        int openParen = method.indexOf('(');
        if (openParen < 0) {
            return null;
        }
        int closeParen = method.lastIndexOf(')');
        if (closeParen <= openParen) {
            return null;
        }
        String arg = method.substring(openParen + 1, closeParen).trim();
        // Strip surrounding quotes if present
        if (arg.startsWith("'") && arg.endsWith("'") && arg.length() >= 2) {
            arg = arg.substring(1, arg.length() - 1);
        } else if (arg.startsWith("\"") && arg.endsWith("\"") && arg.length() >= 2) {
            arg = arg.substring(1, arg.length() - 1);
        }
        return arg.isEmpty() ? null : arg;
    }
}
