package com.huawei.hisec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Loads a generated, versioned SDK factory-product graph and resolves role
 * transitions in official {@code @system:} name paths.
 */
final class SdkFactoryGraph {

    static final String GRAPH_PATH_PROPERTY = "arkprism.sdkFactoryGraph";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static volatile Snapshot snapshot = Snapshot.empty("");
    private static volatile String loadedPath = null;

    private SdkFactoryGraph() {
    }

    static final class Resolution {
        final String productType;
        final String detail;

        Resolution(String productType, String detail) {
            this.productType = productType;
            this.detail = detail;
        }
    }

    static final class RoleResolution {
        final List<Resolution> resolutions;
        final List<SdkFactoryVersionGate.Decision> gateAudit;

        RoleResolution(
                List<Resolution> resolutions,
                List<SdkFactoryVersionGate.Decision> gateAudit) {
            this.resolutions = resolutions;
            this.gateAudit = gateAudit;
        }
    }

    static List<Resolution> resolveRolePath(String resolvedFullName, List<String> rawTokens) {
        return resolveRolePathAudited(resolvedFullName, rawTokens).resolutions;
    }

    static RoleResolution resolveRolePathAudited(
            String resolvedFullName, List<String> rawTokens) {
        Snapshot graph = current();
        if (graph.edges.isEmpty() || resolvedFullName == null
                || !resolvedFullName.startsWith("@system:")
                || rawTokens == null || rawTokens.size() < 2) {
            return new RoleResolution(
                    Collections.emptyList(), Collections.emptyList());
        }

        List<String> tokens = rawTokens.stream()
                .map(NamePathMatcher::stripMethodArguments)
                .map(SdkFactoryGraph::normalize)
                .collect(Collectors.toList());
        int consumerIndex = tokens.size() - 1;
        String consumer = tokens.get(consumerIndex);
        if (consumer.isEmpty()) {
            return new RoleResolution(
                    Collections.emptyList(), Collections.emptyList());
        }

        Map<String, Resolution> resolutions = new LinkedHashMap<>();
        Map<String, SdkFactoryVersionGate.Decision> gateAudit = new LinkedHashMap<>();
        for (int producerIndex = 0; producerIndex < consumerIndex; producerIndex++) {
            String producer = tokens.get(producerIndex);
            if (producer.isEmpty()) continue;

            List<Edge> starts = graph.scopedProducerEdges(
                    resolvedFullName, tokens, producerIndex, producer);
            if (starts.isEmpty()) continue;

            List<State> states = new ArrayList<>();
            for (Edge edge : starts) {
                SdkFactoryVersionGate.Decision decision =
                        SdkFactoryVersionGate.evaluate(
                                edge.importPath,
                                edge.producer,
                                edge.productType,
                                edge.isModuleProducer());
                String auditKey = decision.status + "|" + decision.module + "|"
                        + normalize(decision.producer) + "|" + decision.productType;
                gateAudit.putIfAbsent(auditKey, decision);
                if (decision.allowed) {
                    states.add(new State(edge, List.of(edge), decision));
                }
            }
            if (states.isEmpty()) continue;

            for (int index = producerIndex + 1; index < consumerIndex && !states.isEmpty(); index++) {
                String transitionMethod = tokens.get(index);
                List<State> next = new ArrayList<>();
                for (State state : states) {
                    for (Edge transition : graph.ownerTransitions(
                            state.edge, transitionMethod, resolvedFullName)) {
                        List<Edge> chain = new ArrayList<>(state.chain);
                        chain.add(transition);
                        next.add(new State(
                                transition, chain, state.gateDecision));
                    }
                }
                states = next;
            }

            for (State state : states) {
                if (!state.edge.productMethods.contains(consumer)) continue;
                String key = normalize(state.edge.productType);
                resolutions.putIfAbsent(key, new Resolution(
                        state.edge.productType,
                        graph.describe(
                                state.chain, consumer, state.gateDecision)));
            }
        }
        return new RoleResolution(
                new ArrayList<>(resolutions.values()),
                new ArrayList<>(gateAudit.values()));
    }

    /**
     * Expands a module-level rule namespace to products declared by that
     * module. Concrete product-type rules deliberately remain unexpanded so
     * that sibling products in the same module never become aliases.
     */
    static Set<String> directAliasesForRuleNamespace(String namespace) {
        Snapshot graph = current();
        if (graph.edges.isEmpty() || namespace == null || namespace.isBlank()) {
            return Collections.emptySet();
        }
        String key = normalize(namespace);
        if (graph.productTypes.contains(namespace.trim())) return Collections.emptySet();
        Set<String> products = graph.moduleAliasToProducts.get(key);
        return products == null
                ? Collections.emptySet()
                : new LinkedHashSet<>(products);
    }

    /**
     * Checks the directional relation used by generated factory evidence.
     * A concrete product rule requires exact product identity; a module rule
     * accepts products that the SDK declares under that module alias.
     */
    static boolean productSupportsRule(String productType, String ruleNamespace) {
        Snapshot graph = current();
        if (graph.edges.isEmpty() || productType == null || ruleNamespace == null) {
            return false;
        }
        String product = productType.trim();
        String rule = ruleNamespace.trim();
        if (product.isEmpty() || rule.isEmpty()) return false;
        if (graph.productTypes.contains(rule)) return product.equals(rule);
        Set<String> products = graph.moduleAliasToProducts.get(normalize(rule));
        return products != null && products.contains(normalize(product));
    }

    static String sdkVersion() {
        return current().sdkVersion;
    }

    static String apiVersion() {
        return current().apiVersion;
    }

    static String graphPath() {
        return current().path;
    }

    private static Snapshot current() {
        String configured = System.getProperty(GRAPH_PATH_PROPERTY, "").trim();
        if (Objects.equals(configured, loadedPath)) return snapshot;
        synchronized (SdkFactoryGraph.class) {
            if (Objects.equals(configured, loadedPath)) return snapshot;
            snapshot = load(configured);
            loadedPath = configured;
            return snapshot;
        }
    }

    private static Snapshot load(String configured) {
        if (configured == null || configured.isBlank()) return Snapshot.empty("");
        Path path = Paths.get(configured).toAbsolutePath().normalize();
        if (!Files.isRegularFile(path)) {
            Logger.warn("SDK factory graph does not exist: " + path);
            return Snapshot.empty(path.toString());
        }
        try {
            JsonNode root = MAPPER.readTree(path.toFile());
            JsonNode sdk = root.path("sdk");
            List<Edge> edges = new ArrayList<>();
            for (JsonNode item : root.path("edges")) {
                Edge edge = Edge.from(item);
                if (edge != null) edges.add(edge);
            }
            edges.sort(Comparator.comparing((Edge edge) -> edge.importPath)
                    .thenComparing(edge -> edge.ownerType)
                    .thenComparing(edge -> edge.producer)
                    .thenComparing(edge -> edge.productType)
                    .thenComparing(edge -> edge.id));
            Snapshot result = new Snapshot(
                    path.toString(),
                    sdk.path("version").asText(""),
                    sdk.path("apiVersion").asText(""),
                    edges);
            Logger.log("[+] Loaded SDK factory graph: " + path
                    + " (sdk=" + result.sdkVersion
                    + ", api=" + result.apiVersion
                    + ", edges=" + edges.size() + ")");
            return result;
        } catch (IOException | RuntimeException error) {
            Logger.error("Failed to load SDK factory graph " + path + ": " + error.getMessage());
            return Snapshot.empty(path.toString());
        }
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private static final class State {
        final Edge edge;
        final List<Edge> chain;
        final SdkFactoryVersionGate.Decision gateDecision;

        State(
                Edge edge,
                List<Edge> chain,
                SdkFactoryVersionGate.Decision gateDecision) {
            this.edge = edge;
            this.chain = chain;
            this.gateDecision = gateDecision;
        }
    }

    private static final class Snapshot {
        final String path;
        final String sdkVersion;
        final String apiVersion;
        final List<Edge> edges;
        final Map<String, List<Edge>> producerIndex = new LinkedHashMap<>();
        final Map<String, List<Edge>> ownerProducerIndex = new LinkedHashMap<>();
        final Set<String> productTypes = new LinkedHashSet<>();
        final Map<String, Set<String>> moduleAliasToProducts = new LinkedHashMap<>();

        Snapshot(String path, String sdkVersion, String apiVersion, List<Edge> edges) {
            this.path = path;
            this.sdkVersion = sdkVersion;
            this.apiVersion = apiVersion;
            this.edges = edges;
            for (Edge edge : edges) {
                producerIndex.computeIfAbsent(normalize(edge.producer), ignored -> new ArrayList<>())
                        .add(edge);
                ownerProducerIndex.computeIfAbsent(
                                normalize(edge.ownerType) + "|" + normalize(edge.producer),
                                ignored -> new ArrayList<>())
                        .add(edge);

                String product = normalize(edge.productType);
                productTypes.add(edge.productType.trim());
                for (String alias : edge.moduleAliases) {
                    String normalized = normalize(alias);
                    if (normalized.isEmpty()) continue;
                    moduleAliasToProducts.computeIfAbsent(
                                    normalized, ignored -> new LinkedHashSet<>())
                            .add(product);
                }
            }
        }

        static Snapshot empty(String path) {
            return new Snapshot(path, "", "", Collections.emptyList());
        }

        List<Edge> scopedProducerEdges(
                String resolvedFullName,
                List<String> pathTokens,
                int producerIndex,
                String producer) {
            List<Edge> values = producerIndex().getOrDefault(producer, Collections.emptyList());
            if (values.isEmpty()) return values;

            List<Edge> eligible = values.stream()
                    .filter(edge -> edge.isModuleProducer()
                            || ownerAppearsBefore(pathTokens, producerIndex, edge.ownerType))
                    .collect(Collectors.toList());
            if (eligible.isEmpty()) return Collections.emptyList();
            return selectBestModuleScope(eligible, resolvedFullName);
        }

        private Map<String, List<Edge>> producerIndex() {
            return producerIndex;
        }

        List<Edge> ownerTransitions(Edge current, String producer, String resolvedFullName) {
            String key = normalize(current.productType) + "|" + producer;
            List<Edge> values = ownerProducerIndex.getOrDefault(key, Collections.emptyList());
            if (values.isEmpty()) return values;
            List<Edge> sameModule = values.stream()
                    .filter(edge -> current.moduleKey.equals(edge.moduleKey))
                    .collect(Collectors.toList());
            return selectBestModuleScope(sameModule.isEmpty() ? values : sameModule, resolvedFullName);
        }

        private List<Edge> selectBestModuleScope(List<Edge> values, String resolvedFullName) {
            int best = values.stream()
                    .mapToInt(edge -> edge.moduleMatchScore(resolvedFullName))
                    .max().orElse(0);
            if (best > 0) {
                final int selected = best;
                return values.stream()
                        .filter(edge -> edge.moduleMatchScore(resolvedFullName) == selected)
                        .collect(Collectors.toList());
            }
            return Collections.emptyList();
        }

        String describe(
                List<Edge> chain,
                String consumer,
                SdkFactoryVersionGate.Decision gateDecision) {
            String transitions = chain.stream()
                    .map(edge -> edge.producer + "->" + edge.productType)
                    .collect(Collectors.joining("/"));
            Edge first = chain.get(0);
            Edge last = chain.get(chain.size() - 1);
            return "sdk-graph[api=" + apiVersion
                    + ",module=" + first.importPath
                    + ",chain=" + transitions
                    + ",consumer=" + consumer
                    + ",source=" + last.source + ":" + last.line
                    + ",gate=" + gateDecision.status + "]";
        }

        private static boolean ownerAppearsBefore(
                List<String> pathTokens, int producerIndex, String ownerType) {
            String owner = normalize(ownerType);
            for (int index = 0; index < producerIndex; index++) {
                if (owner.equals(pathTokens.get(index))) return true;
            }
            return false;
        }
    }

    private static final class Edge {
        final String id;
        final String module;
        final String importPath;
        final String moduleNamespace;
        final Set<String> moduleAliases;
        final String moduleKey;
        final String ownerType;
        final String ownerKind;
        final String producer;
        final String productType;
        final Set<String> productMethods;
        final String source;
        final int line;

        Edge(
                String id,
                String module,
                String importPath,
                String moduleNamespace,
                Set<String> moduleAliases,
                String ownerType,
                String ownerKind,
                String producer,
                String productType,
                Set<String> productMethods,
                String source,
                int line) {
            this.id = id;
            this.module = module;
            this.importPath = importPath;
            this.moduleNamespace = moduleNamespace;
            this.moduleAliases = moduleAliases;
            this.moduleKey = normalize(!importPath.isBlank() ? importPath : module);
            this.ownerType = ownerType;
            this.ownerKind = ownerKind;
            this.producer = producer;
            this.productType = productType;
            this.productMethods = productMethods;
            this.source = source;
            this.line = line;
        }

        static Edge from(JsonNode item) {
            String producer = item.path("producer").asText("");
            String product = item.path("productType").asText("");
            if (producer.isBlank() || product.isBlank()) return null;

            String module = item.path("module").asText("");
            String importPath = item.path("importPath").asText("");
            String moduleNamespace = item.path("moduleNamespace").asText("");
            Set<String> aliases = new LinkedHashSet<>();
            for (JsonNode alias : item.path("moduleAliases")) aliases.add(alias.asText());
            aliases.add(importPath);
            aliases.add(moduleNamespace);
            aliases.removeIf(String::isBlank);

            Set<String> methods = new LinkedHashSet<>();
            for (JsonNode method : item.path("productMethods")) {
                String value = method.isTextual()
                        ? method.asText() : method.path("name").asText("");
                value = normalize(NamePathMatcher.stripMethodArguments(value));
                if (!value.isEmpty()) methods.add(value);
            }
            return new Edge(
                    item.path("id").asText(""),
                    module,
                    importPath,
                    moduleNamespace,
                    aliases,
                    item.path("ownerType").asText(moduleNamespace),
                    item.path("ownerKind").asText("module"),
                    producer,
                    product,
                    methods,
                    item.path("source").asText(""),
                    item.path("line").asInt(0));
        }

        boolean isModuleProducer() {
            return "module".equalsIgnoreCase(ownerKind)
                    || normalize(ownerType).equals(normalize(moduleNamespace));
        }

        int moduleMatchScore(String resolvedFullName) {
            String path = normalize(resolvedFullName);
            int score = 0;
            for (String alias : moduleAliases) {
                String normalized = normalize(alias);
                if (!normalized.startsWith("@")) continue;
                String binaryAlias = toBinaryModuleAlias(normalized);
                if (containsModuleAlias(path, normalized)
                        || containsModuleAlias(path, binaryAlias)) {
                    score = Math.max(score, 1000 + binaryAlias.length());
                }
            }
            return score;
        }

        private static String toBinaryModuleAlias(String alias) {
            int separator = alias.indexOf('.');
            return alias.startsWith("@") && separator > 0
                    ? alias.substring(0, separator) + ":" + alias.substring(separator + 1)
                    : alias;
        }

        private static boolean containsModuleAlias(String path, String alias) {
            int fromIndex = 0;
            while (fromIndex <= path.length() - alias.length()) {
                int index = path.indexOf(alias, fromIndex);
                if (index < 0) return false;
                int end = index + alias.length();
                boolean beforeBoundary = index == 0 || !isModuleIdentifier(path.charAt(index - 1));
                boolean afterBoundary = end == path.length() || !isModuleIdentifier(path.charAt(end));
                if (beforeBoundary && afterBoundary) return true;
                fromIndex = index + 1;
            }
            return false;
        }

        private static boolean isModuleIdentifier(char value) {
            return Character.isLetterOrDigit(value) || value == '_' || value == '$';
        }

    }
}
