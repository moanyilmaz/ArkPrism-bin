package com.huawei.hisec;

/**
 * Unified privacy API rule model.
 *
 * Combines fields previously duplicated in PreciseSensitiveApiScanner and PrivacyCatalog.
 * Used by both the ArkTS scanner and the privacy catalog for consistent rule representation.
 */
public class PrivacyApiRule {

    /** Whether this is a direct call rule. null means "unspecified" (treated as constant rule). */
    public Boolean directCall;

    /** SDK namespace (e.g., "geoLocationManager", "wifiManager"). */
    public String namespace;

    /** Method name (e.g., "getCurrentLocation", "getScanInfoList"). */
    public String method;

    /** Permission required to call this API. */
    public String permission;

    /** Profiling category for risk classification. */
    public String profilingCategory;

    /** Logical category (e.g., "LOCATION", "NETWORK"). */
    public String category;

    /** API package path (e.g., "@kit.TelephonyKit"). */
    public String apiPackage;

    /** Data direction: "source" | "sink" | "both" | "excluded". */
    public String dataDirection;

    /** Index of the sensitive argument in the API call (used by PrivacyCatalog). */
    public Integer sensitiveArgIndex;
}
