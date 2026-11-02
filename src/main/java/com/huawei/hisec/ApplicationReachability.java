package com.huawei.hisec;

import com.huawei.hianalyzer.analysis.Stage;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.base.HiFunction;
import com.huawei.hianalyzer.analysis.foreign.ForeignField;
import com.huawei.hianalyzer.analysis.graph.callgraph.CallGraph;
import com.huawei.hianalyzer.ir.stmt.*;
import java.io.File;
import java.util.*;

/** Application-scoped entry reachability, including explicit imports and callbacks. */
public final class ApplicationReachability {
    private static final Set<String> ENTRY_NAMES = Set.of(
            "onCreate", "onDestroy", "onNewWant", "onWindowStageCreate", "onWindowStageDestroy",
            "onForeground", "onBackground", "onContinue", "onRequest", "onConnect", "onDisconnect",
            "onAcceptWant", "onConfigurationUpdate", "onMemoryLevel", "onSessionCreate", "onSessionDestroy",
            "build", "initialRender", "rerender", "aboutToAppear", "aboutToDisappear",
            "onPageShow", "onPageHide", "onBackPress", "onClick", "onChange", "onTouch", "onReady");

    private final Map<HiFunction, File> origins = new IdentityHashMap<>();
    private final Map<HiFunction, Set<HiFunction>> edges = new IdentityHashMap<>();
    private final Map<String, Set<HiFunction>> symbols = new HashMap<>();
    private final Map<HiFunction, HiFunction> predecessors = new IdentityHashMap<>();
    private final Set<HiFunction> roots = identitySet();
    private final Set<HiFunction> unknown = identitySet();
    private final Set<HiFunction> unresolvedCallers = identitySet();
    private final Set<HiFunction> libraryFunctions = identitySet();
    private final HiFile merged;
    private final File applicationDirectory;
    private final boolean enabled;
    private boolean complete;

    public ApplicationReachability(Map<File, HiFile> files, File applicationDirectory, boolean complete) {
        this.applicationDirectory = applicationDirectory;
        this.complete = complete;
        this.enabled = Boolean.parseBoolean(System.getProperty("filter.library.apis", "true"));
        this.merged = files.values().iterator().next();
        // addOtherHiFile rewrites getFile(); preserve identity and provenance before merging.
        for (Map.Entry<File, HiFile> file : files.entrySet()) {
            for (HiFunction function : file.getValue().getHiFunctions()) {
                origins.put(function, file.getKey());
                if (isLibrary(file.getKey(), applicationDirectory) || isLibraryRecord(function.getPackageName())) libraryFunctions.add(function);
                edges.put(function, identitySet());
                String module = normalizeModule(function.getPackageName());
                String owner = function.getDeclaringClass().getName();
                addSymbol(module + "." + owner + "." + function.getName(), function);
                if ("#GLOBAL".equals(owner)) addSymbol(module + "." + function.getName(), function);
                if (!libraryFunctions.contains(function)
                        && (function.isModuleEntry() || ENTRY_NAMES.contains(function.getName()))) roots.add(function);
                if (libraryFunctions.contains(function)
                        && (function.isModuleEntry() || ENTRY_NAMES.contains(function.getName())
                        || function.getName().matches("on[A-Z].*"))) unknown.add(function);
            }
        }
        for (HiFile file : files.values()) if (file != merged) merged.addOtherHiFile(file);
    }

    public HiFile mergedFile() { return merged; }
    public File applicationDirectory() { return applicationDirectory; }
    public boolean isLibraryCall(Stmt stmt) { return stmt != null && libraryFunctions.contains(stmt.getHiFunction()); }

    public List<HiFunction> pathTo(Stmt stmt) {
        if (stmt == null || !predecessors.containsKey(stmt.getHiFunction())) return List.of();
        List<HiFunction> path = new ArrayList<>();
        for (HiFunction current = stmt.getHiFunction(); current != null; current = predecessors.get(current)) path.add(current);
        Collections.reverse(path);
        return path;
    }

    public File origin(Stmt stmt) {
        return stmt == null ? null : origins.get(stmt.getHiFunction());
    }

    public void analyze(CallGraph graph) {
        if (libraryFunctions.isEmpty()) {
            Logger.log("[Reachability] no identified library functions; preserving the application scan");
            return;
        }
        if (graph == null) complete = false;
        for (HiFunction function : origins.keySet()) {
            try {
                if (function.getBody() == null) { unresolvedCallers.add(function); continue; }
                Map<String, Set<HiFunction>> values = new HashMap<>();
                List<Stmt> statements = function.getBody().getStmts();
                // Fixed point handles SSA phi/copy aliases and callback values.
                boolean changed;
                do {
                    changed = false;
                    for (Stmt stmt : statements) {
                        if (!ReachabilityAnalyzer.isReachableFromEntry(stmt)) continue;
                        Set<HiFunction> targets = identitySet();
                        String local = null;
                        if (stmt instanceof FunctionAssignStmt assign) {
                            local = assign.getLValue().getFullName();
                            if (assign.getRValue().resolve() instanceof HiFunction target && origins.containsKey(target)) targets.add(target);
                        } else if (stmt instanceof LocalAssignStmt assign) {
                            local = assign.getLValue().getFullName();
                            targets.addAll(values.getOrDefault(assign.getRValue().getFullName(), Set.of()));
                        } else if (stmt instanceof RFieldAssignStmt assign) {
                            local = assign.getLValue().getFullName();
                            if (assign.getFieldRef().resolve() instanceof ForeignField field) {
                                targets.addAll(resolve(field.getFromPath() + "." + field.getImportName()));
                            }
                        } else if (stmt instanceof DefinitionStmt<?, ?> assign
                                && !(stmt instanceof CallStmt) && assign.getLValue() instanceof com.huawei.hianalyzer.ir.value.Local value) {
                            local = value.getFullName();
                            for (var use : stmt.getUses()) if (use instanceof com.huawei.hianalyzer.ir.value.Local alias)
                                targets.addAll(values.getOrDefault(alias.getFullName(), Set.of()));
                        }
                        if (local != null && values.computeIfAbsent(local, k -> identitySet()).addAll(targets)) changed = true;
                    }
                } while (changed);

                // Loading a known module also executes its initializer.
                if (function.isModuleEntry()) {
                    for (ForeignField field : merged.getForeignFields()) {
                        if (!Objects.equals(normalizeModule(field.getPackageName()), normalizeModule(function.getPackageName()))) continue;
                        for (HiFunction target : resolve(field.getFromPath() + ".func_main_0")) edges.get(function).add(target);
                    }
                }
                for (Stmt stmt : statements) {
                    if (!(stmt instanceof CallStmt call) || !ReachabilityAnalyzer.isReachableFromEntry(stmt)) continue;
                    Set<HiFunction> targets = identitySet();
                    if (graph != null) {
                        Set<HiFunction> callees = graph.getCalleesByCallSite(call);
                        if (callees != null) for (HiFunction target : callees) if (origins.containsKey(target)) targets.add(target);
                    }
                    if (call.getFunctionRef().resolve() instanceof HiFunction target && origins.containsKey(target)) targets.add(target);
                    String api = merged.getFullApiNameByStmt(call);
                    if (api != null) targets.addAll(resolve(api));
                    if (call.getFunctionRef().getFunctionLocal() != null) {
                        targets.addAll(values.getOrDefault(call.getFunctionRef().getFunctionLocal().getFullName(), Set.of()));
                    }
                    edges.get(function).addAll(targets);
                    boolean unresolvedCallback = false;
                    for (var argument : call.getCallExpr().getArgList()) {
                        Set<HiFunction> callbacks = values.getOrDefault(argument.getFullName(), Set.of());
                        edges.get(function).addAll(callbacks);
                        if (callbacks.isEmpty() && argument.getType() instanceof com.huawei.hianalyzer.common.type.FunctionType) unresolvedCallback = true;
                    }
                    // Known platform calls terminate here; a missing internal/virtual target
                    // may reach any library function and cannot justify deletion.
                    if ((targets.isEmpty() && !isPlatformCall(api, call.toString())) || unresolvedCallback) unresolvedCallers.add(function);
                }
            } catch (RuntimeException | LinkageError exception) {
                unresolvedCallers.add(function);
            }
        }
        ArrayDeque<HiFunction> queue = new ArrayDeque<>();
        for (HiFunction root : roots) { predecessors.put(root, null); queue.add(root); }
        while (!queue.isEmpty()) {
            HiFunction current = queue.remove();
            for (HiFunction target : edges.getOrDefault(current, Set.of())) {
                if (!predecessors.containsKey(target)) { predecessors.put(target, current); queue.add(target); }
            }
        }
        for (HiFunction function : origins.keySet()) {
            if (predecessors.containsKey(function) && unresolvedCallers.contains(function)) complete = false;
        }
        // Framework-driven library lifecycle and initializer code remains possible.
        queue.addAll(unknown);
        while (!queue.isEmpty()) for (HiFunction target : edges.getOrDefault(queue.remove(), Set.of())) if (unknown.add(target)) queue.add(target);
        for (HiFunction function : unknown) if (unresolvedCallers.contains(function)) complete = false;
        Logger.log("[Reachability] application=" + applicationDirectory.getName() + ", roots=" + roots.size()
                + ", reachableFunctions=" + predecessors.size() + ", complete=" + complete);
        ReachabilityAnalyzer.clearCache();
    }

    public UnifiedPrivacyReport.EntryReachability classify(Stmt stmt) {
        UnifiedPrivacyReport.EntryReachability result = new UnifiedPrivacyReport.EntryReachability();
        if (!enabled) { result.status = "unknown"; result.reason = "filter_disabled"; return result; }
        HiFunction function = stmt == null ? null : stmt.getHiFunction();
        if (function != null && predecessors.containsKey(function)) {
            result.status = ReachabilityAnalyzer.isReachableFromEntry(stmt) ? "reachable" : "unreachable";
            result.reason = result.status.equals("reachable") ? "application_entry_path" : "unreachable_statement";
            for (HiFunction current = function; current != null; current = predecessors.get(current)) {
                File file = origins.get(current);
                result.path.add(relative(file) + " :: " + current.getSignature());
            }
            Collections.reverse(result.path);
        } else if (function == null || !origins.containsKey(function) || roots.isEmpty() || !complete || unknown.contains(function)) {
            result.status = "unknown";
            result.reason = function == null ? "missing_call_site" : roots.isEmpty() ? "no_application_entries"
                    : unknown.contains(function) ? "framework_or_initializer" : "incomplete_call_resolution";
        } else {
            result.status = "unreachable";
            result.reason = "no_application_entry_path";
        }
        return result;
    }

    private String relative(File file) {
        return file == null ? "<unknown>" : applicationDirectory.toPath().toAbsolutePath().normalize()
                .relativize(file.toPath().toAbsolutePath().normalize()).toString().replace('\\', '/');
    }

    public String relativeOrigin(Stmt stmt) { return relative(origin(stmt)); }

    public String functionIdentity(Stmt stmt) {
        return stmt == null || stmt.getHiFunction() == null ? "<unknown>" : stmt.getHiFunction().getSignature().toString();
    }

    public static boolean isLibrary(File file, File applicationDirectory) {
        if (file == null) return false;
        java.nio.file.Path root = applicationDirectory.toPath().toAbsolutePath().normalize();
        java.nio.file.Path path = file.toPath().toAbsolutePath().normalize();
        if (!path.startsWith(root)) return false;
        // Inspect the entire module path; module.json inside a scoped module must
        // not hide the enclosing @scope. Never inspect directories outside the app.
        for (java.nio.file.Path part : root.relativize(path)) if (part.toString().startsWith("@")) return true;
        return applicationDirectory.getName().startsWith("@");
    }

    private void addSymbol(String name, HiFunction function) { symbols.computeIfAbsent(name, k -> identitySet()).add(function); }
    private static boolean isLibraryRecord(String record) {
        return record != null && (record.contains("/oh_modules/") || record.contains("/node_modules/")
                || record.contains(".oh_modules.") || record.contains(".node_modules."));
    }
    private Set<HiFunction> resolve(String name) {
        // The frontend dot-encodes relative imports. Parent-relative paths require
        // importer-context resolution; never collapse them onto an unrelated module.
        if (name != null && name.startsWith("@system:...")) return Set.of();
        return symbols.getOrDefault(normalizeModule(name), Set.of());
    }
    private static String normalizeModule(String value) {
        if (value == null) return "";
        return value.replaceFirst("^@(bundle|system|import):", "").replace('\\', '.').replace('/', '.').replaceFirst("^\\.+", "");
    }
    private static boolean isPlatformCall(String api, String statement) {
        String name = api == null ? statement : api;
        return name.startsWith("@internal:ArkInternal.ThrowIf.") || name.startsWith("@internal:ArkInternal.ArkLanguage.")
                || name.contains("@ohos") || name.contains("@kit")
                || name.contains("@arkui") || name.contains("@native:");
    }
    private static Set<HiFunction> identitySet() { return Collections.newSetFromMap(new IdentityHashMap<>()); }
}
