package com.huawei.hisec;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Unified report model for binary-side analysis.
 *
 * Design Goals:
 * 1. ArkTS/.abc hits: preserve CHAIN, call chains with method bodies, data flow to SINK, purposeHint.
 * 2. Native/.so hits: write directly to privacyApiUsages, not involved in ArkTS call chain and data flow.
 * 3. Output format should align with source-side reports: privacyApiUsages + callChains + semanticContext.
 */
public class UnifiedPrivacyReport {

    /**
     * Unified output interface version.
     * Both source and binary analysis tools should use this field.
     */
    public String schemaVersion = "1.0";

    /**
     * Analysis mode:
     * source / binary / hybrid
     *
     * Binary tool is fixed to binary.
     */
    public String analysisMode = "binary";

    public String projectName;
    public String projectDirectory;
    public String analysisTimestamp;

    /**
     * All API hit points.
     *
     * Contains both ArkTS and Native so hits.
     * Distinction fields:
     * - sourceLayer = "ArkTS" or "Native"
     * - sourceKind = "API_MAP" / "FIELD_MAP" / "ELF_IMPORT" / "ELF_STRING"
     */
    public List<ApiUsage> privacyApiUsages = new ArrayList<>();

    /**
     * Only ArkTS/.abc layer participates in multi-source collaboration detection.
     * Native/.so hits do not participate in this analysis.
     */
    public List<MultiSourceCollaboration> multiSourceCollaborations = new ArrayList<>();

    /**
     * Only ArkTS/.abc hits generate call chains.
     * Native/.so hits do not generate call chains.
     */
    public List<CallChainReport> callChains = new ArrayList<>();

    /**
     * Runtime summary.
     */
    public Summary summary = new Summary();


    // ======================================================
    // 1. API Hit Points
    // ======================================================

    public static class ApiUsage {
        /**
         * Which layer this hit belongs to.
         * ArkTS / Native
         */
        public String sourceLayer;

        /**
         * Hit source.
         * ArkTS:
         *   API_MAP / FIELD_MAP
         *
         * Native:
         *   ELF_IMPORT / ELF_STRING
         */
        public String sourceKind;

        /**
         * Hit type.
         * For example:
         * - privacy constants
         * - direct invoke stmt after assignment
         * - native import symbol
         * - native string reference
         * - media_file_access
         */
        public String category;

        /**
         * API package.
         * ArkTS example: @kit.BasicServicesKit
         * Native example: OpenHarmony.Native.DeviceInfo
         */
        public String apiPackage;

        /**
         * Namespace.
         * ArkTS example: deviceInfo / geoLocationManager
         * Native example: libvideoCompressor.so / libxxx.so
         */
        public String namespace;

        /**
         * Method name.
         */
        public String method;

        /**
         * Arguments.
         * ArkTS: can be parsed from Stmt;
         * Native: usually empty.
         */
        public List<String> args = new ArrayList<>();

        /**
         * Hit code or evidence.
         * ArkTS: IR stmt text.
         * Native: symbol/prototype/evidence summary.
         */
        public String code;

        /**
         * File path.
         * ArkTS: abc filename or original ets path.
         * Native: so file path.
         */
        public String file;

        /**
         * Declaring method.
         * ArkTS: current HiFunction.
         * Native: empty if no function-level location; to be filled if PLT caller is implemented.
         */
        public String declaringMethod;

        /**
         * Permission.
         * Filled if exists in rule library, null otherwise.
         */
        public String permission;

        /**
         * Profiling category.
         * Examples:
         * - device_identity.hardware
         * - location
         * - network.connectivity
         * - media.content
         */
        public String profilingCategory;

        /**
         * Data direction: "source" (reads sensitive data) | "sink" (outputs/stores sensitive data).
         * Null if unknown or not applicable.
         */
        public String dataDirection;

        /**
         * Native legacy flat fields: kept internally in Java, hidden in JSON output.
         * Native evidence is uniformly output to nativeEvidence.
         */
        @JsonIgnore
        public String prototype;

        @JsonIgnore
        public String symbol;

        @JsonIgnore
        public String arch;

        @JsonIgnore
        public String soName;

        @JsonIgnore
        public String matchType;

        // confidence: high/medium/low — set by CFG reachability check, @import filter, etc.
        public String confidence;

        @JsonIgnore
        public String risk;

        @JsonIgnore
        public Map<String, Object> evidence;

        /**
         * Native/.so specific evidence.
         * Null for ArkTS hits, not output in JSON.
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public NativeEvidence nativeEvidence;
    }

// ======================================================
// 1.1 Native Evidence Object
// ======================================================

    public static class NativeEvidence {
        /**
         * Native API full C function signature.
         * Example: const char *OH_GetDeviceType(void)
         */
        public String prototype;

        /**
         * Raw symbol parsed from ELF.
         */
        public String symbol;

        /**
         * ELF architecture.
         * Examples: AARCH64 / ARMEL / AMD64
         */
        public String arch;

        /**
         * So filename.
         */
        public String soName;

        /**
         * Match type.
         * import_symbol / string_reference
         */
        public String matchType;

        /**
         * Hit confidence.
         * high / medium / low
         */
        public String confidence;

        /**
         * Raw evidence.
         * Example: reloc_addr, resolved_addr, string_addr.
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public Map<String, Object> evidence;
    }


    // ======================================================
    // 2. Call Chain Reports
    // ======================================================

    public static class CallChainReport {
        public int apiUsageIndex;

        public EntryMethod entryMethod;

        public List<CallEdge> chain = new ArrayList<>();

        /**
         * Control structure information.
         * Currently not recovered in binary ABC analysis, defaults to empty array.
         */
        public List<ControlStructure> controlStructures = new ArrayList<>();

        public List<SourceSnippet> sourceSnippets = new ArrayList<>();

        public List<DataSink> dataSinks = new ArrayList<>();

        public SemanticContext semanticContext;
    }


    public static class EntryMethod {
        public String name;
        public String type;
        public String file;
        public int line = -1;
    }


    public static class CallEdge {
        public String caller;
        public String callee;

        /**
         * direct / callback / lifecycle / unknown
         */
        public String callType;

        public String resolvedCallerName;
        public String resolvedCalleeName;
    }

    // ======================================================
    // 2.1 Control Structure Information
    // ======================================================

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ControlStructure {
        /**
         * Control structure type:
         * if / try_catch / loop / switch / unknown
         */
        public String type;

        /**
         * Conditional expression.
         * Example: %0 === %1
         */
        public String condition;

        public String file;

        /**
         * Fill with -1 if source line number is not available.
         */
        public int line = -1;

        /**
         * Whether current control structure contains sensitive API call.
         */
        public Boolean containsApiCall;

        /**
         * true_branch / false_branch / try_block / catch_block / unknown
         */
        public String branchSide;

        /**
         * Whether this is a guard condition (permission check, environment check, etc.).
         */
        public Boolean isGuardCondition;

        /**
         * Whether this control structure dominates sensitive API call.
         */
        public Boolean isDominatingApiCall;

        /**
         * Whether try-catch has catch fallback.
         */
        public Boolean hasCatchFallback;
    }


    public static class SourceSnippet {
        public String method;
        public String file;
        public int startLine = -1;
        public int endLine = -1;

        /**
         * IR code.
         */
        public String code;

        /**
         * Fill if source code can be recovered later.
         * Currently empty for binary analysis.
         */
        public String originalCode;
    }


    public static class DataSink {
        /**
         * log / network / storage / upload / unknown
         */
        public String sinkType;

        public String sinkApi;
        public String sinkMethod;
        public String sinkFile;
        public int sinkLine = -1;
    }


    public static class SemanticContext {
        public String pageName;
        public String componentClass;
        public String semanticAnchor;
        public String simplifiedChain;
        public String purposeHint;
    }


    // ======================================================
    // 3. Summary
    // ======================================================

    public static class Summary {
        /**
         * Total number of privacyApiUsages.
         */
        public int totalApiUsages;

        /**
         * ArkTS / ABC layer API hit count.
         * Source analysis tools can also count source-layer hits here.
         */
        public int arktsApiUsages;

        /**
         * Native / SO layer API hit count.
         * Fill with 0 if source analysis tool has no Native analysis.
         */
        public int nativeApiUsages;

        /**
         * Call chain count。
         */
        public int callChainCount;

        /**
         * Control structure count。
         * Binary ABC currently does not recover control structures, usually 0.
         */
        public int controlStructureCount;

        /**
         * Method body snippet count.
         */
        public int sourceSnippetCount;

        /**
         * Data sink count。
         * Usually 0 when binary ABC IFDS is disabled.
         */
        public int dataSinkCount;

        /**
         * Multi-source collaboration group count.
         */
        public int multiSourceCollaborationCount;

        /**
         * Analyzed object statistics.
         */
        public int analyzedHapCount;
        public int analyzedAbcCount;
        public int analyzedSoCount;

        /**
         * Non-fatal issues.
         */
        public List<String> warnings = new ArrayList<>();
    }

    // ======================================================
    // 4. Multi-Source Collaboration Report
    // ======================================================

    public static class MultiSourceCollaboration {
        /**
         * Hit combination rule ID.
         * Example: DEVICE_PROFILE_BASIC / LOCATION_WIFI_PROFILE.
         */
        public String ruleId;

        /**
         * Hit combination rule name.
         */
        public String ruleName;

        /**
         * Detection level:
         * same_method / lca / same_file
         */
        public String detectionLevel;

        /**
         * Simplified name of the lowest common ancestor method.
         */
        public String lcaMethod;

        /**
         * Full signature of the lowest common ancestor method.
         */
        public String lcaMethodSig;

        /**
         * Semantic entry method name.
         */
        public String entryMethod;

        /**
         * Aggregated profiling categories.
         */
        public List<String> categories = new ArrayList<>();

        /**
         * APIs involved in collaboration.
         */
        public List<CollaborationApi> apis = new ArrayList<>();

        /**
         * low / medium / high
         */
        public String riskLevel;

        /**
         * Reason why this collaboration group is formed.
         */
        public String reason;

        /**
         * high / medium / low
         */
        public String confidence;

        /**
         * Subgraph structure.
         */
        public CollaborationSubgraph subgraph;
    }


    public static class CollaborationApi {
        /**
         * Index corresponding to privacyApiUsages.
         */
        public int apiUsageIndex = -1;

        /**
         * Example: deviceInfo.productModel / geoLocationManager.getCurrentLocation.
         */
        public String api;

        /**
         * Example: device_identity.hardware / location / network.wifi.
         */
        public String category;

        public String namespace;
        public String method;
        public String declaringMethod;
        public String file;
    }


    public static class CollaborationSubgraph {
        /**
         * Path from entry to LCA.
         */
        public List<CallEdge> entryToLca = new ArrayList<>();

        /**
         * Entry method.
         */
        public EntryMethod entry;

        /**
         * LCA full signature.
         */
        public String lcaMethodSig;

        /**
         * Branches from LCA to each sensitive API.
         */
        public List<CollaborationBranch> branches = new ArrayList<>();

        /**
         * Overall semantics of multi-source collaboration group.
         */
        public SemanticContext semanticContext;
    }


    public static class CollaborationBranch {
        public int apiUsageIndex = -1;

        public String api;
        public String category;
        public String declaringMethod;

        /**
         * Path from LCA to the method containing sensitive API.
         */
        public List<CallEdge> lcaToSource = new ArrayList<>();

        /**
         * Currently empty by default.
         * Because IFDS is temporarily disabled, unreliable sinks are not output.
         */
        public List<DataSink> sinks = new ArrayList<>();
    }
}