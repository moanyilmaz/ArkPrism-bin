package com.huawei.hisec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * Selectively admits module-level factory edges using versioned official SDK
 * declarations. Class-owner edges and non-OpenHarmony modules remain outside
 * this policy's evidence scope.
 */
final class SdkFactoryVersionGate {

    static final String POLICY_PATH_PROPERTY = "arkprism.sdkFactoryVersionPolicy";
    static final String TARGET_API_PROPERTY = "arkprism.targetApiLevel";
    static final String UNKNOWN_MODE_PROPERTY = "arkprism.sdkFactoryUnknownVersionMode";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static volatile PolicySnapshot snapshot = PolicySnapshot.disabled("");
    private static volatile String loadedPath = null;

    private SdkFactoryVersionGate() {
    }

    static Decision evaluate(
            String module,
            String producer,
            String productType,
            boolean moduleProducer) {
        String configured = System.getProperty(POLICY_PATH_PROPERTY, "").trim();
        String normalizedModule = normalize(module);
        if (configured.isEmpty()) {
            return Decision.allow(
                    "POLICY_DISABLED", null, null, null,
                    normalizedModule, producer, productType,
                    Collections.emptySet(), Collections.emptySet());
        }
        if (!moduleProducer) {
            return Decision.allow(
                    "CLASS_OWNER_OUTSIDE_SCOPE", targetApiLevel(), null, null,
                    normalizedModule, producer, productType,
                    Collections.emptySet(), Collections.emptySet());
        }

        PolicySnapshot policy = current();
        if (!normalizedModule.startsWith(policy.modulePrefix)) {
            return Decision.allow(
                    "MODULE_OUTSIDE_SCOPE", targetApiLevel(), null, null,
                    normalizedModule, producer, productType,
                    Collections.emptySet(), Collections.emptySet());
        }
        if (!policy.available) {
            return Decision.reject(
                    "REJECT_POLICY_UNAVAILABLE", targetApiLevel(), null, null,
                    normalizedModule, producer, productType,
                    Collections.emptySet(), Collections.emptySet());
        }

        Integer target = targetApiLevel();
        if (target == null) {
            if ("strict".equals(unknownMode())) {
                return Decision.reject(
                        "REJECT_NO_TARGET_API", null, null, null,
                        normalizedModule, producer, productType,
                        Collections.emptySet(), Collections.emptySet());
            }
            return Decision.allow(
                    "UNVERSIONED_FALLBACK", null, null, null,
                    normalizedModule, producer, productType,
                    Collections.emptySet(), Collections.emptySet());
        }

        String query = queryKey(normalizedModule, producer);
        Map<String, Set<String>> exact = policy.snapshots.get(target);
        if (exact != null) {
            Set<String> candidates = exact.getOrDefault(query, Collections.emptySet());
            if (candidates.contains(productType)) {
                return Decision.allow(
                        "EXACT_SNAPSHOT", target, target, target,
                        normalizedModule, producer, productType,
                        candidates, candidates);
            }
            return Decision.reject(
                    "REJECT_EXACT_EDGE_ABSENT", target, target, target,
                    normalizedModule, producer, productType,
                    candidates, candidates);
        }

        Integer lower = policy.snapshots.lowerKey(target);
        Integer upper = policy.snapshots.higherKey(target);
        if (lower == null || upper == null) {
            return Decision.reject(
                    "REJECT_NO_BRACKET", target, lower, upper,
                    normalizedModule, producer, productType,
                    Collections.emptySet(), Collections.emptySet());
        }
        Set<String> lowerProducts = policy.snapshots.get(lower)
                .getOrDefault(query, Collections.emptySet());
        Set<String> upperProducts = policy.snapshots.get(upper)
                .getOrDefault(query, Collections.emptySet());
        if (lowerProducts.isEmpty()) {
            return Decision.reject(
                    "REJECT_LOWER_MISSING", target, lower, upper,
                    normalizedModule, producer, productType,
                    lowerProducts, upperProducts);
        }
        if (upperProducts.isEmpty()) {
            return Decision.reject(
                    "REJECT_UPPER_MISSING", target, lower, upper,
                    normalizedModule, producer, productType,
                    lowerProducts, upperProducts);
        }
        if (!lowerProducts.equals(upperProducts)) {
            return Decision.reject(
                    "REJECT_BRACKET_DRIFT", target, lower, upper,
                    normalizedModule, producer, productType,
                    lowerProducts, upperProducts);
        }
        if (!lowerProducts.contains(productType)) {
            return Decision.reject(
                    "REJECT_PRODUCT_ABSENT", target, lower, upper,
                    normalizedModule, producer, productType,
                    lowerProducts, upperProducts);
        }
        return Decision.allow(
                "BRACKET_CONSENSUS", target, lower, upper,
                normalizedModule, producer, productType,
                lowerProducts, upperProducts);
    }

    static String policyPath() {
        return current().path;
    }

    static Integer targetApiLevel() {
        String value = System.getProperty(TARGET_API_PROPERTY, "").trim();
        if (value.isEmpty()) return null;
        try {
            int result = Integer.parseInt(value);
            return result > 0 ? result : null;
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    static String unknownMode() {
        String value = System.getProperty(UNKNOWN_MODE_PROPERTY, "preserve")
                .trim().toLowerCase(Locale.ROOT);
        return "strict".equals(value) ? "strict" : "preserve";
    }

    private static PolicySnapshot current() {
        String configured = System.getProperty(POLICY_PATH_PROPERTY, "").trim();
        if (Objects.equals(configured, loadedPath)) return snapshot;
        synchronized (SdkFactoryVersionGate.class) {
            if (Objects.equals(configured, loadedPath)) return snapshot;
            snapshot = load(configured);
            loadedPath = configured;
            return snapshot;
        }
    }

    private static PolicySnapshot load(String configured) {
        if (configured == null || configured.isBlank()) {
            return PolicySnapshot.disabled("");
        }
        Path path = Paths.get(configured).toAbsolutePath().normalize();
        if (!Files.isRegularFile(path)) {
            Logger.warn("SDK factory version policy does not exist: " + path);
            return PolicySnapshot.unavailable(path.toString());
        }
        try {
            JsonNode root = MAPPER.readTree(path.toFile());
            if (root.path("schemaVersion").asInt(0) != 1
                    || !root.path("snapshots").isArray()) {
                Logger.warn("Unsupported SDK factory version policy: " + path);
                return PolicySnapshot.unavailable(path.toString());
            }
            String modulePrefix = normalize(
                    root.path("scope").path("modulePrefix").asText("@ohos."));
            TreeMap<Integer, Map<String, Set<String>>> snapshots = new TreeMap<>();
            for (JsonNode snapshotNode : root.path("snapshots")) {
                int apiLevel = snapshotNode.path("apiLevel").asInt(0);
                if (apiLevel <= 0) continue;
                Map<String, Set<String>> queries = new LinkedHashMap<>();
                for (JsonNode queryNode : snapshotNode.path("queries")) {
                    String module = queryNode.path("module").asText("");
                    String producer = queryNode.path("producer").asText("");
                    String key = queryKey(module, producer);
                    if (key.equals("|")) continue;
                    Set<String> products = new LinkedHashSet<>();
                    for (JsonNode product : queryNode.path("productTypes")) {
                        String value = product.asText("").trim();
                        if (!value.isEmpty()) products.add(value);
                    }
                    if (!products.isEmpty()) {
                        queries.put(key, Collections.unmodifiableSet(products));
                    }
                }
                snapshots.put(apiLevel, Collections.unmodifiableMap(queries));
            }
            if (snapshots.isEmpty()) {
                return PolicySnapshot.unavailable(path.toString());
            }
            PolicySnapshot result = new PolicySnapshot(
                    path.toString(), modulePrefix, snapshots, true);
            Logger.log("[+] Loaded SDK factory version policy: " + path
                    + " (snapshots=" + snapshots.size()
                    + ", apiLevels=" + new ArrayList<>(snapshots.keySet()) + ")");
            return result;
        } catch (IOException | RuntimeException error) {
            Logger.error("Failed to load SDK factory version policy "
                    + path + ": " + error.getMessage());
            return PolicySnapshot.unavailable(path.toString());
        }
    }

    private static String queryKey(String module, String producer) {
        return normalize(module) + "|" + normalize(producer);
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    static final class Decision {
        final boolean allowed;
        final String status;
        final Integer targetApiLevel;
        final Integer lowerApiLevel;
        final Integer upperApiLevel;
        final String module;
        final String producer;
        final String productType;
        final Set<String> lowerProducts;
        final Set<String> upperProducts;

        private Decision(
                boolean allowed,
                String status,
                Integer targetApiLevel,
                Integer lowerApiLevel,
                Integer upperApiLevel,
                String module,
                String producer,
                String productType,
                Set<String> lowerProducts,
                Set<String> upperProducts) {
            this.allowed = allowed;
            this.status = status;
            this.targetApiLevel = targetApiLevel;
            this.lowerApiLevel = lowerApiLevel;
            this.upperApiLevel = upperApiLevel;
            this.module = module;
            this.producer = producer;
            this.productType = productType;
            this.lowerProducts = new LinkedHashSet<>(lowerProducts);
            this.upperProducts = new LinkedHashSet<>(upperProducts);
        }

        static Decision allow(
                String status,
                Integer targetApiLevel,
                Integer lowerApiLevel,
                Integer upperApiLevel,
                String module,
                String producer,
                String productType,
                Set<String> lowerProducts,
                Set<String> upperProducts) {
            return new Decision(
                    true, status, targetApiLevel, lowerApiLevel, upperApiLevel,
                    module, producer, productType, lowerProducts, upperProducts);
        }

        static Decision reject(
                String status,
                Integer targetApiLevel,
                Integer lowerApiLevel,
                Integer upperApiLevel,
                String module,
                String producer,
                String productType,
                Set<String> lowerProducts,
                Set<String> upperProducts) {
            return new Decision(
                    false, status, targetApiLevel, lowerApiLevel, upperApiLevel,
                    module, producer, productType, lowerProducts, upperProducts);
        }

        String detail() {
            return "version-gate[status=" + status
                    + ",target=" + (targetApiLevel == null ? "" : targetApiLevel)
                    + ",lower=" + (lowerApiLevel == null ? "" : lowerApiLevel)
                    + ",upper=" + (upperApiLevel == null ? "" : upperApiLevel)
                    + ",module=" + module
                    + ",producer=" + producer
                    + ",product=" + productType + "]";
        }

        Map<String, Object> toRecord() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("allowed", allowed);
            result.put("status", status);
            result.put("targetApiLevel", targetApiLevel);
            result.put("lowerApiLevel", lowerApiLevel);
            result.put("upperApiLevel", upperApiLevel);
            result.put("module", module);
            result.put("producer", producer);
            result.put("productType", productType);
            result.put("lowerProducts", new ArrayList<>(lowerProducts));
            result.put("upperProducts", new ArrayList<>(upperProducts));
            return result;
        }
    }

    private static final class PolicySnapshot {
        final String path;
        final String modulePrefix;
        final TreeMap<Integer, Map<String, Set<String>>> snapshots;
        final boolean available;

        PolicySnapshot(
                String path,
                String modulePrefix,
                TreeMap<Integer, Map<String, Set<String>>> snapshots,
                boolean available) {
            this.path = path;
            this.modulePrefix = modulePrefix.isEmpty() ? "@ohos." : modulePrefix;
            this.snapshots = snapshots;
            this.available = available;
        }

        static PolicySnapshot disabled(String path) {
            return new PolicySnapshot(path, "@ohos.", new TreeMap<>(), false);
        }

        static PolicySnapshot unavailable(String path) {
            return new PolicySnapshot(path, "@ohos.", new TreeMap<>(), false);
        }
    }
}
