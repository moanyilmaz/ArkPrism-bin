package com.huawei.hisec;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Loads the reviewed ArkTS API catalog and converts each source row into the
 * scanner's internal rule model.
 */
public final class PrivacyApiConfigLoader {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private PrivacyApiConfigLoader() {
    }

    public static final class LoadedRule {
        public final String systemPackage;
        public final PrivacyApiRule rule;

        LoadedRule(String systemPackage, PrivacyApiRule rule) {
            this.systemPackage = systemPackage;
            this.rule = rule;
        }
    }

    public static List<LoadedRule> load(File file) throws IOException {
        JsonNode root = MAPPER.readTree(file);
        if (root == null || !root.isArray()) {
            throw new IOException("Privacy API catalog must be a JSON array: " + file);
        }
        if (root.isEmpty()) {
            return new ArrayList<>();
        }

        JsonNode first = root.get(0);
        if (first.has("api_signature")) {
            return loadReviewedCatalog(root, file);
        }
        return loadLegacyCatalog(file);
    }

    private static List<LoadedRule> loadReviewedCatalog(JsonNode root, File file)
            throws IOException {
        List<LoadedRule> rules = new ArrayList<>(root.size());
        Map<String, String> mappingByApi = new HashMap<>();

        for (int i = 0; i < root.size(); i++) {
            JsonNode item = root.get(i);
            String apiSignature = requiredText(item, "api_signature", i, file);
            String callCategory = requiredText(item, "call_catagory", i, file);
            String dataType = requiredText(item, "dataType", i, file);
            String label = requiredText(item, "label", i, file);
            String importKit = requiredText(item, "import_kit", i, file);

            SignatureParts parts = splitApiSignature(apiSignature, i, file);
            Boolean directCall;
            if ("直接调用".equals(callCategory)) {
                directCall = Boolean.TRUE;
            } else if ("间接调用".equals(callCategory)) {
                directCall = Boolean.FALSE;
            } else {
                throw new IOException("Unsupported call_catagory at row " + i
                        + ": " + callCategory);
            }

            String mapping = dataType + "\u0000" + label;
            String previous = mappingByApi.putIfAbsent(apiSignature, mapping);
            if (previous != null && !previous.equals(mapping)) {
                throw new IOException("Conflicting dataType/label mapping for "
                        + apiSignature + " at row " + i);
            }

            PrivacyApiRule rule = new PrivacyApiRule();
            rule.directCall = directCall;
            rule.namespace = parts.namespace;
            rule.method = parts.method;
            rule.permission = nullableText(item, "permission");
            rule.profilingCategory = dataType;
            rule.apiPackage = importKit;
            rule.dataDirection = "source";
            rule.dataType = dataType;
            rule.label = label;
            rule.apiSignature = apiSignature;
            rule.apiKeyword = text(item, "api_kwd");
            rule.callCategory = callCategory;
            rule.moduleTitle = text(item, "possible_module_title");
            rule.sdkModule = extractSdkModule(rule.moduleTitle);
            rule.moduleAlias = extractModuleAlias(rule.moduleTitle);
            rule.signatureDescription = text(item, "descrip0");
            rule.description = text(item, "descrip1");
            rule.constraintDescription = text(item, "descrip2");
            rule.supplement = text(item, "supplement");
            rule.documentationPath = text(item, "URL_postfix");
            rule.catalogRow = i;

            ArgumentRange range = parseArgumentRange(rule.signatureDescription);
            rule.minimumArgumentCount = range.minimum;
            rule.maximumArgumentCount = range.maximum;

            rules.add(new LoadedRule(importKit, rule));
        }

        return rules;
    }

    private static List<LoadedRule> loadLegacyCatalog(File file) throws IOException {
        List<LegacyPackage> packages = MAPPER.readValue(
                file, new TypeReference<List<LegacyPackage>>() { });
        List<LoadedRule> rules = new ArrayList<>();
        if (packages == null) {
            return rules;
        }
        for (LegacyPackage pkg : packages) {
            if (pkg == null || pkg.privacyApis == null) {
                continue;
            }
            for (PrivacyApiRule rule : pkg.privacyApis) {
                if (rule != null) {
                    rules.add(new LoadedRule(pkg.systemPackage, rule));
                }
            }
        }
        return rules;
    }

    private static String requiredText(JsonNode item, String field, int row, File file)
            throws IOException {
        String value = text(item, field);
        if (value == null || value.isBlank()) {
            throw new IOException("Missing " + field + " at row " + row + " in " + file);
        }
        return value;
    }

    private static String text(JsonNode item, String field) {
        JsonNode value = item == null ? null : item.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        return value.asText();
    }

    private static String nullableText(JsonNode item, String field) {
        String value = text(item, field);
        if (value == null || value.isBlank() || "null".equalsIgnoreCase(value.trim())) {
            return null;
        }
        return value.trim();
    }

    private static SignatureParts splitApiSignature(String signature, int row, File file)
            throws IOException {
        int openParen = signature.indexOf('(');
        String base = openParen >= 0 ? signature.substring(0, openParen) : signature;
        int separator = base.lastIndexOf('.');
        if (separator < 0) {
            String method = base.trim()
                    + (openParen >= 0 ? signature.substring(openParen) : "");
            if (method.isEmpty()) {
                throw new IOException("Invalid api_signature at row " + row
                        + " in " + file + ": " + signature);
            }
            return new SignatureParts("", method);
        }
        if (separator == 0 || separator >= base.length() - 1) {
            throw new IOException("Invalid api_signature at row " + row
                    + " in " + file + ": " + signature);
        }
        String namespace = base.substring(0, separator).trim();
        String method = base.substring(separator + 1).trim()
                + (openParen >= 0 ? signature.substring(openParen) : "");
        return new SignatureParts(namespace, method);
    }

    private static String extractSdkModule(String moduleTitle) {
        if (moduleTitle == null) {
            return null;
        }
        String value = moduleTitle.trim();
        if (!(value.startsWith("@ohos.") || value.startsWith("@hms."))) {
            return null;
        }
        int end = value.length();
        int space = value.indexOf(' ');
        int asciiParen = value.indexOf('(');
        int chineseParen = value.indexOf('（');
        if (space >= 0) end = Math.min(end, space);
        if (asciiParen >= 0) end = Math.min(end, asciiParen);
        if (chineseParen >= 0) end = Math.min(end, chineseParen);
        return value.substring(0, end).trim();
    }

    private static String extractModuleAlias(String moduleTitle) {
        if (moduleTitle == null) {
            return null;
        }
        String value = moduleTitle.trim();
        int end = value.length();
        int asciiParen = value.indexOf('(');
        int chineseParen = value.indexOf('（');
        if (asciiParen >= 0) end = Math.min(end, asciiParen);
        if (chineseParen >= 0) end = Math.min(end, chineseParen);
        String alias = value.substring(0, end).trim();
        if (alias.isEmpty() || alias.startsWith("@")
                || "Interface".equalsIgnoreCase(alias)
                || "Class".equalsIgnoreCase(alias)) {
            return null;
        }
        return alias;
    }

    private static ArgumentRange parseArgumentRange(String signatureDescription) {
        if (signatureDescription == null) {
            return ArgumentRange.unknown();
        }
        int open = signatureDescription.indexOf('(');
        if (open < 0) {
            return ArgumentRange.unknown();
        }
        int close = findMatchingParenthesis(signatureDescription, open);
        if (close < 0) {
            return ArgumentRange.unknown();
        }
        String parameters = signatureDescription.substring(open + 1, close).trim();
        if (parameters.isEmpty()) {
            return new ArgumentRange(0, 0);
        }

        List<String> parts = splitTopLevel(parameters);
        int minimum = 0;
        int maximum = 0;
        for (String parameter : parts) {
            String value = parameter.trim();
            if (value.isEmpty()) {
                continue;
            }
            maximum++;
            int colon = value.indexOf(':');
            String name = colon >= 0 ? value.substring(0, colon).trim() : value;
            if (!name.endsWith("?") && !name.startsWith("...")) {
                minimum++;
            }
        }
        return new ArgumentRange(minimum, maximum);
    }

    private static int findMatchingParenthesis(String value, int open) {
        int depth = 0;
        for (int i = open; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch == '(') depth++;
            if (ch == ')' && --depth == 0) return i;
        }
        return -1;
    }

    private static List<String> splitTopLevel(String value) {
        List<String> parts = new ArrayList<>();
        int angle = 0;
        int round = 0;
        int square = 0;
        int start = 0;
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '<': angle++; break;
                case '>': angle = Math.max(0, angle - 1); break;
                case '(': round++; break;
                case ')': round = Math.max(0, round - 1); break;
                case '[': square++; break;
                case ']': square = Math.max(0, square - 1); break;
                case ',':
                    if (angle == 0 && round == 0 && square == 0) {
                        parts.add(value.substring(start, i));
                        start = i + 1;
                    }
                    break;
                default:
                    break;
            }
        }
        parts.add(value.substring(start));
        return parts;
    }

    private static final class SignatureParts {
        final String namespace;
        final String method;

        SignatureParts(String namespace, String method) {
            this.namespace = namespace;
            this.method = method;
        }
    }

    private static final class ArgumentRange {
        final Integer minimum;
        final Integer maximum;

        ArgumentRange(Integer minimum, Integer maximum) {
            this.minimum = minimum;
            this.maximum = maximum;
        }

        static ArgumentRange unknown() {
            return new ArgumentRange(null, null);
        }
    }

    private static final class LegacyPackage {
        public String systemPackage;
        public List<PrivacyApiRule> privacyApis;
    }
}
