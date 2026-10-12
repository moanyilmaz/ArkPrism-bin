package com.huawei.hisec;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Writes one JSON object per indirect call site when the
 * {@code arkprism.binding.trace} system property is set.
 */
final class BindingExperimentTrace {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private BindingExperimentTrace() {
    }

    static synchronized void record(List<CaiResolver.ResolutionResult> results) {
        String output = System.getProperty("arkprism.binding.trace", "").trim();
        if (output.isEmpty() || results == null || results.isEmpty()) return;

        Path path = Paths.get(output).toAbsolutePath().normalize();
        try {
            Path parent = path.getParent();
            if (parent != null) Files.createDirectories(parent);
            try (BufferedWriter writer = Files.newBufferedWriter(
                    path,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND)) {
                for (CaiResolver.ResolutionResult result : results) {
                    writer.write(MAPPER.writeValueAsString(toRecord(result)));
                    writer.newLine();
                }
            }
        } catch (IOException e) {
            Logger.error("[-] Failed to write binding experiment trace: " + e.getMessage());
        }
    }

    private static Map<String, Object> toRecord(CaiResolver.ResolutionResult result) {
        CaiResolver.CallSiteInfo site = result.callSite;
        int stmtIndex = ScannerUtils.safeStmtIndex(site.stmt);
        String appId = System.getProperty("arkprism.experiment.appId", "unknown");
        String statement = safe(site.stmt);
        String functionSignature = functionSignature(site);

        Map<String, Object> record = new LinkedHashMap<>();
        record.put("traceVersion", 2);
        record.put("appId", appId);
        record.put("siteId", sha256(appId + "\n" + site.fileName + "\n"
                + functionSignature + "\n" + stmtIndex + "\n" + statement));
        record.put("file", site.fileName);
        record.put("function", site.functionName);
        record.put("functionSignature", functionSignature);
        record.put("stmtIndex", stmtIndex);
        record.put("stmtClass", site.stmt != null ? site.stmt.getClass().getName() : null);
        record.put("statement", statement);
        record.put("resolvedFullName", site.resolvedFullName);
        record.put("method", site.methodName);
        record.put("aliasComponentId", site.aliasComponentId);
        record.put("componentNamespace", site.componentNamespace);
        record.put("outlier", site.isOutlier);
        record.put("outcome", result.bestCandidate == null
                ? "NO_CANDIDATE" : result.isAmbiguous ? "ABSTAIN" : "BIND");
        record.put("ambiguous", result.isAmbiguous);
        record.put("entropy", result.entropy);
        record.put("top1Top2Margin", scoreMargin(result.allCandidates));
        record.put("riskControl", CaiResolver.RISK_CONTROL);
        record.put("roleAwareEvidence", CaiResolver.ROLE_AWARE_EVIDENCE);
        record.put("factoryRoleSource", CaiResolver.FACTORY_ROLE_SOURCE);
        record.put("sdkFactoryGraph", SdkFactoryGraph.graphPath());
        record.put("sdkFactoryGraphVersion", SdkFactoryGraph.sdkVersion());
        record.put("sdkFactoryGraphApiVersion", SdkFactoryGraph.apiVersion());
        record.put("sdkFactoryVersionPolicy", SdkFactoryVersionGate.policyPath());
        record.put("sdkFactoryTargetApiLevel", SdkFactoryVersionGate.targetApiLevel());
        record.put("sdkFactoryUnknownVersionMode", SdkFactoryVersionGate.unknownMode());
        record.put("gamma", CaiResolver.CONFLICT_PENALTY_GAMMA);
        record.put("lambda", CaiResolver.CONSISTENCY_PENALTY_LAMBDA);

        if (result.bestCandidate != null) {
            record.put("bestCandidate", candidateRecord(result.bestCandidate));
        } else {
            record.put("bestCandidate", null);
        }

        List<Map<String, Object>> candidates = new ArrayList<>();
        for (CaiResolver.CandidateApi candidate : result.allCandidates) {
            candidates.add(candidateRecord(candidate));
        }
        record.put("candidates", candidates);

        List<Map<String, Object>> evidence = new ArrayList<>();
        for (CaiResolver.NamespaceEvidence item : site.evidence) {
            Map<String, Object> value = new LinkedHashMap<>();
            value.put("kind", item.kind.name());
            value.put("namespace", item.namespace);
            value.put("canonicalNamespace", CaiResolver.getCanonicalNamespaceKey(item.namespace));
            value.put("weight", item.weight);
            value.put("detail", item.detail);
            value.put("supportsBestCandidate", result.bestCandidate != null
                    && CaiResolver.evidenceSupportsNamespace(
                    item, result.bestCandidate.namespace));
            evidence.add(value);
        }
        record.put("evidence", evidence);

        List<Map<String, Object>> gateAudit = new ArrayList<>();
        for (SdkFactoryVersionGate.Decision decision : site.factoryGateAudit) {
            gateAudit.add(decision.toRecord());
        }
        record.put("factoryGateAudit", gateAudit);

        if (result.certificate != null) {
            Map<String, Object> certificate = new LinkedHashMap<>();
            certificate.put("componentNamespace", result.certificate.componentNamespace);
            certificate.put("rationale", result.certificate.decisionRationale);
            certificate.put("rejectionReasons", result.certificate.rejectionReasons);
            record.put("certificate", certificate);
        }

        return record;
    }

    private static Map<String, Object> candidateRecord(CaiResolver.CandidateApi candidate) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("namespace", candidate.namespace);
        value.put("canonicalNamespace", CaiResolver.getCanonicalNamespaceKey(candidate.namespace));
        value.put("method", candidate.methodName);
        value.put("systemPackage", candidate.rule.systemPackage);
        value.put("score", candidate.score);
        value.put("supportScore", candidate.supportScore);
        return value;
    }

    private static Double scoreMargin(List<CaiResolver.CandidateApi> candidates) {
        Map<String, Double> scores = new LinkedHashMap<>();
        for (CaiResolver.CandidateApi candidate : candidates) {
            String namespace = CaiResolver.getCanonicalNamespaceKey(candidate.namespace);
            scores.merge(namespace, candidate.score,
                    CaiResolver.RISK_CONTROL ? Math::max : Double::sum);
        }
        if (scores.size() < 2) return null;
        List<Double> ordered = new ArrayList<>(scores.values());
        ordered.sort(Comparator.reverseOrder());
        return ordered.get(0) - ordered.get(1);
    }

    private static String safe(Object value) {
        if (value == null) return "";
        try {
            return String.valueOf(value);
        } catch (Throwable ignored) {
            return "<unprintable>";
        }
    }

    private static String functionSignature(CaiResolver.CallSiteInfo site) {
        try {
            if (site != null && site.stmt != null && site.stmt.getHiFunction() != null
                    && site.stmt.getHiFunction().getSignature() != null) {
                return site.stmt.getHiFunction().getSignature().toString();
            }
        } catch (Throwable ignored) {
        }
        return site != null ? site.functionName : "";
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(bytes.length * 2);
            for (byte item : bytes) hex.append(String.format("%02x", item));
            return hex.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
