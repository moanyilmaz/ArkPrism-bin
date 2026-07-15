package com.huawei.hisec;

/**
 * Ambiguity model for CAIR's resolution decisions.
 *
 * Replaces the binary GENERIC_METHOD_BLACKLIST with continuous ambiguity assessment.
 * A resolution is marked as ambiguous when the evidence entropy exceeds a threshold,
 * meaning multiple namespaces compete for the same call site with similar evidence strength.
 *
 * Key differences from GENERIC_METHOD_BLACKLIST:
 * 1. Continuous: entropy provides a real-valued ambiguity score, not just in/out.
 * 2. Evidence-aware: if strong evidence (e.g., PTA uniquely identifies a class)
 *    supports a "generic" method, the ambiguity is low and the match is accepted.
 * 3. Composable: ambiguity scores can be combined across alias components.
 */
public class AmbiguityModel {

    /** Entropy threshold (in bits) above which a resolution is marked ambiguous. */
    public static final double AMBIGUITY_THRESHOLD = 1.5;

    /** Minimum confidence score required to accept a non-ambiguous resolution. */
    public static final double MIN_CONFIDENCE = 0.4;

    /**
     * Determines if a method name is inherently ambiguous (appears in many namespaces).
     * These are the same methods as in GENERIC_METHOD_BLACKLIST, but the assessment
     * is evidence-dependent rather than absolute: if PTA or static type evidence
     * uniquely identifies the namespace, the ambiguity can be overridden.
     */
    public static boolean isInherentlyAmbiguous(String methodName) {
        if (methodName == null) return false;
        String lower = methodName.toLowerCase(java.util.Locale.ROOT);
        return GENERIC_METHODS.contains(lower);
    }

    /**
     * The set of generic verb method names that are inherently ambiguous.
     * When matched by method name alone (no namespace evidence), these produce
     * unreliable results and should be treated with caution.
     */
    private static final java.util.Set<String> GENERIC_METHODS = java.util.Set.of(
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

    /**
     * Computes the effective ambiguity for a resolution, considering both
     * entropy and inherent method ambiguity.
     *
     * @param entropy Computed entropy from namespace score distribution
     * @param methodName The matched method name
     * @param hasStrongEvidence Whether PTA_CLASS or STATIC_TYPE evidence is present
     * @return true if the resolution should be treated as ambiguous
     */
    public static boolean isAmbiguous(double entropy, String methodName, boolean hasStrongEvidence) {
        // Strong evidence (PTA or static type uniquely identifying a class)
        // can override the inherent ambiguity of generic methods.
        if (hasStrongEvidence && entropy < AMBIGUITY_THRESHOLD) {
            return false;
        }
        // No strong evidence + generic method → always ambiguous
        if (!hasStrongEvidence && isInherentlyAmbiguous(methodName)) {
            return true;
        }
        // Otherwise, use entropy threshold
        return entropy > AMBIGUITY_THRESHOLD;
    }
}
