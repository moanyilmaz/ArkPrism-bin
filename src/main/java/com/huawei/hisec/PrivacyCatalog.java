package com.huawei.hisec;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.ir.stmt.CallStmt;
import com.huawei.hianalyzer.ir.stmt.Stmt;

import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * Privacy Source & Sink Catalog.
 *
 * Loads source/sink patterns from privacy_apis.json.
 * Follows FlowDroid/SuSi declarative approach: each API has an explicit
 * dataDirection field ("source" | "sink" | "both" | "excluded").
 *
 * dataDirection takes precedence over profilingCategory inference.
 * The inference fallback only handles JSON files without dataDirection.
 */
public class PrivacyCatalog {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    /**
     * Source API patterns: namespace + method (e.g. "geoLocationManager.getCurrentLocation").
     */
    private final Set<String> sourcePatterns = new HashSet<>();

    /**
     * Sink API patterns: namespace + method (e.g. "http.request").
     * Also stores "@system:@ohos:" prefix variant.
     */
    private final Set<String> sinkPatterns = new HashSet<>();

    /**
     * Category index: profilingCategory -> Set of source patterns.
     * For multi-source collaboration detection.
     */
    private final Map<String, Set<String>> sourceByCategory = new HashMap<>();

    public PrivacyCatalog(String jsonPath) {
        loadFromJson(jsonPath);
    }

    // ======================================================
    // Source API Detection
    // ======================================================

    /**
     * Checks if the given API matches any known source pattern.
     *
     * Supports two API name formats:
     * - Short: "geoLocationManager.getCurrentLocation"
     * - Full:  "@system:@ohos:geoLocationManager.getCurrentLocation"
     *
     * Also handles module-prefixed variants:
     * - "multimedia.audio.createAudioCapturer" matches "audio.createAudioCapturer"
     */
    public boolean isSourceApi(HiFile hiFile, CallStmt callStmt) {
        String apiName = safeGetFullApiName(hiFile, callStmt);
        if (apiName == null) return false;

        String normalized = stripOhosPrefix(apiName);

        if (sourcePatterns.contains(normalized)) return true;
        if (sourcePatterns.contains(apiName)) return true;

        // Method-level suffix match for module-prefixed variants
        int lastDot = normalized.lastIndexOf('.');
        if (lastDot > 0) {
            String methodFull = normalized.substring(lastDot);
            for (String pattern : sourcePatterns) {
                int patLastDot = pattern.lastIndexOf('.');
                if (patLastDot > 0) {
                    String patMethod = pattern.substring(patLastDot);
                    if (methodFull.equals(patMethod)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Checks if the API name contains any known source namespace.
     */
    public boolean containsSourceNamespace(String apiName) {
        if (apiName == null) return false;
        for (String pattern : sourcePatterns) {
            int dotIdx = pattern.indexOf('.');
            if (dotIdx > 0) {
                String ns = pattern.substring(0, dotIdx);
                if (apiName.contains(ns)) {
                    return true;
                }
            }
        }
        return false;
    }

    // ======================================================
    // Def-Use Analysis
    // ======================================================

    /**
     * Checks if the given stmt defines a value that is actually USED later.
     */
    public boolean isValueUsed(Stmt stmt) {
        try {
            var uses = stmt.getUses();
            return uses != null && !uses.isEmpty();
        } catch (Throwable t) {
            return true;  // Fail-open
        }
    }

    // ======================================================
    // Getters
    // ======================================================

    public Set<String> getSourcePatterns() {
        return Collections.unmodifiableSet(sourcePatterns);
    }

    public Set<String> getSinkPatterns() {
        return Collections.unmodifiableSet(sinkPatterns);
    }

    public Set<String> getSourcesByCategory(String category) {
        return sourceByCategory.getOrDefault(category, Collections.emptySet());
    }

    // ======================================================
    // Loading
    // ======================================================

    /**
     * Loads API patterns from privacy_apis.json.
     *
     * Direction resolution (in priority order):
     * 1. Explicit dataDirection field in JSON rule (source/sink/both/excluded)
     * 2. Fallback: infer from profilingCategory (for backward compatibility)
     *
     * "excluded" APIs are skipped — they go into neither sourcePatterns nor sinkPatterns.
     */
    private void loadFromJson(String jsonPath) {
        if (jsonPath == null || jsonPath.isBlank()) return;

        File f = new File(jsonPath);
        if (!f.exists()) return;

        try {
            List<PrivacyApiPackage> packages = MAPPER.readValue(
                    f, new TypeReference<List<PrivacyApiPackage>>() {}
            );

            int sourceCount = 0, sinkCount = 0, excludedCount = 0, unknownCount = 0;

            for (PrivacyApiPackage pkg : packages) {
                if (pkg.privacyApis == null) continue;

                for (PrivacyApiRule rule : pkg.privacyApis) {
                    if (rule.namespace == null || rule.method == null) continue;

                    String fullName = rule.namespace + "." + rule.method;
                    String direction = resolveDirection(rule);

                    if ("excluded".equals(direction)) {
                        excludedCount++;
                        continue;
                    }

                    if ("source".equals(direction) || "both".equals(direction)) {
                        sourcePatterns.add(fullName);
                        sourceCount++;

                        String cat = rule.profilingCategory;
                        if (cat != null) {
                            sourceByCategory.computeIfAbsent(cat, k -> new HashSet<>()).add(fullName);
                        }
                    }

                    if ("sink".equals(direction) || "both".equals(direction)) {
                        sinkPatterns.add(fullName);
                        sinkPatterns.add("@system:@ohos:" + fullName);
                        sinkCount++;
                    }

                    if (direction == null) {
                        unknownCount++;
                    }
                }
            }

            Logger.log("[PrivacyCatalog] Loaded from " + jsonPath
                    + ": sources=" + sourceCount
                    + ", sinks=" + sinkCount
                    + (excludedCount > 0 ? ", excluded=" + excludedCount : "")
                    + (unknownCount > 0 ? ", unresolved=" + unknownCount : ""));

        } catch (IOException e) {
            Logger.error("[PrivacyCatalog] Failed to load " + jsonPath + ": " + e.getMessage());
        }
    }

    /**
     * Resolves the data direction for a rule.
     *
     * Priority:
     * 1. Explicit dataDirection field
     * 2. Fallback: infer from profilingCategory (backward compatibility only)
     */
    private String resolveDirection(PrivacyApiRule rule) {
        // Explicit declaration takes precedence
        if (rule.dataDirection != null && !rule.dataDirection.isBlank()) {
            return rule.dataDirection.trim().toLowerCase(Locale.ROOT);
        }

        // Fallback: infer from profilingCategory (only for old JSON without dataDirection)
        return inferDirection(rule.profilingCategory);
    }

    /**
     * Infers data direction from profilingCategory.
     * Only used as fallback when dataDirection field is absent.
     */
    private String inferDirection(String profilingCategory) {
        if (profilingCategory == null) return null;
        String lower = profilingCategory.toLowerCase(Locale.ROOT);

        // EXCLUDED: non-personally-identifying hardware/UI info
        if (lower.equals("device_identity.screen") ||
            lower.equals("device_status.battery") ||
            lower.equals("device_status.uptime") ||
            lower.equals("device_status.vibrator")) {
            return "excluded";
        }

        // SOURCE
        if (lower.equals("location") ||
            lower.startsWith("device_identity.") ||
            lower.startsWith("device_status.") ||
            lower.startsWith("media.") ||
            lower.startsWith("user_data") ||
            lower.startsWith("user_behavior") ||
            lower.startsWith("user_preference") ||
            lower.startsWith("user_interaction") ||
            lower.equals("app_environment") ||
            lower.startsWith("app_environment.")) {
            return "source";
        }

        // SINK
        if (lower.startsWith("network.") ||
            lower.startsWith("data_storage") ||
            lower.equals("app_analytics") ||
            lower.startsWith("app_analytics") ||
            lower.equals("app_behavior") ||
            lower.startsWith("app_behavior.")) {
            return "sink";
        }

        return null;
    }

    // ======================================================
    // JSON model classes
    // ======================================================

    public static class PrivacyApiPackage {
        public String systemPackage;
        public String category;
        public List<PrivacyApiRule> privacyApis;
    }

    public static class PrivacyApiRule {
        public String namespace;
        public String method;
        public String category;
        public String profilingCategory;
        public String permission;
        /**
         * Explicit data direction declaration.
         * "source" | "sink" | "both" | "excluded"
         * Takes precedence over profilingCategory inference.
         */
        public String dataDirection;
        public Integer sensitiveArgIndex;
    }

    // ======================================================
    // Utility
    // ======================================================

    private static String stripOhosPrefix(String apiName) {
        if (apiName != null && apiName.startsWith("@system:@ohos:")) {
            return apiName.substring("@system:@ohos:".length());
        }
        return apiName;
    }

    private static String safeGetFullApiName(HiFile hiFile, CallStmt callStmt) {
        try {
            return hiFile.getFullApiNameByStmt(callStmt);
        } catch (Throwable t) {
            return null;
        }
    }
}