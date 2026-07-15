package com.huawei.hisec;

import java.util.*;

/**
 * Ambiguity model for CAIR's resolution decisions.
 *
 * Combines three sources of ambiguity assessment:
 * 1. Catalog-derived: how many namespaces contain this method in the rule catalog?
 * 2. Entropy-based: how uniform is the score distribution across candidate namespaces?
 * 3. Inherently ambiguous: hardcoded list of generic verb methods known to be high-ambiguity.
 *
 * The adaptive threshold adjusts based on catalog entropy:
 *   τ(m) = τ₀ - α * H_catalog(m)
 * Methods that appear in many namespaces get a lower effective threshold,
 * making them more likely to be flagged as ambiguous.
 */
public class AmbiguityModel {

    /** Base entropy threshold (in bits) above which a resolution is marked ambiguous. */
    public static final double AMBIGUITY_THRESHOLD = 1.5;

    /** Minimum confidence score required to accept a non-ambiguous resolution. */
    public static final double MIN_CONFIDENCE = 0.4;

    /** Scaling factor for catalog entropy's influence on the adaptive threshold. */
    public static final double CATALOG_ENTROPY_ALPHA = 0.3;

    // ======================================================
    // Catalog-derived ambiguity analysis
    // ======================================================

    /** For each method name (lowercase), how many distinct canonical namespaces contain it. */
    private static final Map<String, Integer> methodNamespaceCount = new HashMap<>();

    /** For each method name (lowercase), the catalog entropy H_catalog(m). */
    private static final Map<String, Double> methodCatalogEntropy = new HashMap<>();

    /** Whether catalog analysis has been performed. */
    private static boolean catalogAnalyzed = false;

    /**
     * Analyzes the rule catalog to compute per-method namespace counts and catalog entropy.
     * Must be called once before using isAmbiguous() with catalog-aware logic.
     *
     * H_catalog(m) = -Σ p(n|m) * log2(p(n|m))
     * where p(n|m) is uniform across all namespaces containing method m.
     *
     * @param indirectRules Privacy API rules with directCall=false
     */
    public static void analyzeCatalog(List<PreciseSensitiveApiScanner.PrivacyApiRuleWithPkg> indirectRules) {
        methodNamespaceCount.clear();
        methodCatalogEntropy.clear();

        // Build: method → Set<canonical namespace>
        Map<String, Set<String>> methodToCanonicalNs = new LinkedHashMap<>();
        for (var item : indirectRules) {
            String baseMethod = NamePathMatcher.stripMethodArguments(item.rule.method);
            if (baseMethod == null || baseMethod.isEmpty()) continue;
            String ns = item.rule.namespace != null ? item.rule.namespace.toLowerCase(Locale.ROOT) : "";
            String canonicalNs = NamespaceResolver.getCanonicalNamespace(ns);
            String key = canonicalNs + "|" + baseMethod.toLowerCase(Locale.ROOT);
            methodToCanonicalNs.computeIfAbsent(baseMethod.toLowerCase(Locale.ROOT), k -> new LinkedHashSet<>())
                    .add(key);
        }

        // Compute namespace counts and catalog entropy for each method
        for (var entry : methodToCanonicalNs.entrySet()) {
            String method = entry.getKey();
            int n = entry.getValue().size();
            methodNamespaceCount.put(method, n);
            // Catalog entropy: uniform distribution across n namespaces
            if (n > 1) {
                double p = 1.0 / n;
                double h = -(n * p * (Math.log(p) / Math.log(2)));
                methodCatalogEntropy.put(method, h);
            } else {
                methodCatalogEntropy.put(method, 0.0);
            }
        }
        catalogAnalyzed = true;
    }

    /**
     * Gets the number of distinct canonical namespaces containing this method.
     */
    public static int getMethodNamespaceCount(String methodName) {
        if (methodName == null || !catalogAnalyzed) return 0;
        return methodNamespaceCount.getOrDefault(methodName.toLowerCase(Locale.ROOT), 0);
    }

    /**
     * Gets the catalog entropy for this method.
     */
    public static double getMethodCatalogEntropy(String methodName) {
        if (methodName == null || !catalogAnalyzed) return 0.0;
        return methodCatalogEntropy.getOrDefault(methodName.toLowerCase(Locale.ROOT), 0.0);
    }

    // ======================================================
    // Inherently ambiguous method detection (fast-path)
    // ======================================================

    /**
     * Determines if a method name is inherently ambiguous (appears in many namespaces).
     * These are generic verb methods that, when matched by name alone (no namespace evidence),
     * produce unreliable results and should be treated with caution.
     */
    public static boolean isInherentlyAmbiguous(String methodName) {
        if (methodName == null) return false;
        String lower = methodName.toLowerCase(Locale.ROOT);
        return GENERIC_METHODS.contains(lower);
    }

    /**
     * The set of generic verb method names that are inherently ambiguous.
     * When matched by method name alone (no namespace evidence), these produce
     * unreliable results and should be treated with caution.
     */
    private static final Set<String> GENERIC_METHODS = Set.of(
            "register", "unregister",
            "start", "stop", "restart",
            "on", "off",
            "open", "close",
            "connect", "disconnect",
            "send", "receive",
            "get", "set",
            "add", "remove",
            "enable", "disable",
            "init", "destroy",
            "load", "save",
            "create", "delete",
            "read", "write",
            "lock", "unlock",
            "bind", "unbind",
            "subscribe", "unsubscribe",
            "show", "hide",
            "play", "pause", "resume",
            // Extended: common verbs that appear unique in rules but are actually generic
            "request", "response",
            "execute", "run", "call", "invoke",
            "update", "refresh", "reset",
            "check", "verify", "validate",
            "process", "handle", "callback",
            "notify", "trigger", "dispatch",
            "release", "cancel", "abort"
    );

    // ======================================================
    // Ambiguity assessment
    // ======================================================

    /**
     * Computes the effective ambiguity for a resolution, considering both
     * entropy and inherent method ambiguity, with an adaptive threshold
     * derived from the rule catalog.
     *
     * Adaptive threshold: τ(m) = τ₀ - α * H_catalog(m)
     * Methods appearing in many namespaces get a lower effective threshold,
     * making them more likely to be flagged as ambiguous.
     *
     * @param entropy Computed entropy from namespace score distribution
     * @param methodName The matched method name
     * @param hasStrongEvidence Whether PTA_CLASS or STATIC_TYPE evidence is present
     * @return true if the resolution should be treated as ambiguous
     */
    public static boolean isAmbiguous(double entropy, String methodName, boolean hasStrongEvidence) {
        // Compute adaptive threshold based on catalog entropy
        double catalogH = catalogAnalyzed ? getMethodCatalogEntropy(methodName) : 0.0;
        double adaptiveThreshold = AMBIGUITY_THRESHOLD - CATALOG_ENTROPY_ALPHA * catalogH;

        // Strong evidence (PTA or static type uniquely identifying a class)
        // can override the inherent ambiguity of generic methods.
        if (hasStrongEvidence && entropy < adaptiveThreshold) {
            return false;
        }
        // No strong evidence + generic method → always ambiguous
        if (!hasStrongEvidence && isInherentlyAmbiguous(methodName)) {
            return true;
        }
        // Otherwise, use adaptive entropy threshold
        return entropy > adaptiveThreshold;
    }
}
