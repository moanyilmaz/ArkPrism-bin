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

    /** Reviewed PAC data type. */
    public String dataType;

    /** Reviewed PAC label. */
    public String label;

    /** Exact API identity from the reviewed catalog. */
    public String apiSignature;

    /** Keyword retained from the reviewed catalog for validation only. */
    public String apiKeyword;

    /** Reviewed direct/indirect call category. */
    public String callCategory;

    /** Human-readable SDK module title from the reviewed catalog. */
    public String moduleTitle;

    /** Machine-readable SDK module when moduleTitle contains one. */
    public String sdkModule;

    /** Reviewed module/object name usable as optional receiver evidence. */
    public String moduleAlias;

    /** SDK declaration used to infer the accepted argument-count range. */
    public String signatureDescription;

    /** Official behavior description. */
    public String description;

    /** Permission, capability, or availability description. */
    public String constraintDescription;

    /** Additional reviewed note. */
    public String supplement;

    /** Documentation path recorded by the reviewed catalog. */
    public String documentationPath;

    /** Zero-based row in the reviewed catalog. */
    public Integer catalogRow;

    /** Minimum and maximum explicit arguments parsed from signatureDescription. */
    public Integer minimumArgumentCount;
    public Integer maximumArgumentCount;

    /** Index of the sensitive argument in the API call (used by PrivacyCatalog). */
    public Integer sensitiveArgIndex;
}
