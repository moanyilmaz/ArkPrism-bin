package com.huawei.hisec;

import com.huawei.hianalyzer.analysis.Stage;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.base.HiFunction;
import com.huawei.hianalyzer.analysis.graph.callgraph.CallGraph;
import com.huawei.hianalyzer.ir.stmt.Stmt;

import java.util.*;

public class CallGraphExplorer {

    // ======================================================
    // Call Chain Data Model
    // ======================================================
    public static class CallChain {
        public HiFunction rootNode; // Business entry function (e.g. onClick)
        public HiFunction sinkNode; // Function containing sensitive API call
        public List<HiFunction> path; // Complete call path (forward: Root -> ... -> Sink)

        /**
         * The specific sink statement that this chain traces.
         * When non-null, this chain is attributed to a particular API call site
         * within sinkNode. When null, the chain applies to all sinks in sinkNode.
         *
         * This field enables per-call-site chain attribution: when multiple API
         * invocations exist in the same function, each gets its own CallChain
         * object with a distinct sinkStmt, allowing downstream code to associate
         * chains with specific apiUsageIndex values.
         */
        public Stmt sinkStmt;
    }

    // ======================================================
    // Compatible method: builds call graph internally (if CallGraph is not passed in)
    // ======================================================
    public static List<CallChain> extractPrivacyCallChains(HiFile hiFile, Set<Stmt> sinkStmts) {
        Logger.log("[*] CallGraphExplorer: Enabling ANDERSEN (PTA) algorithm to build high-precision call graph...");
        CallGraph cg = Stage.createCallGraph(hiFile, CallGraph.CGBuildMethod.ANDERSEN, true);
        return extractPrivacyCallChains(hiFile, cg, sinkStmts);
    }

    // ======================================================
    // Core overloaded method: accepts external CallGraph for improved analysis speed
    // ======================================================
    public static List<CallChain> extractPrivacyCallChains(HiFile hiFile, CallGraph cg, Set<Stmt> sinkStmts) {
        if (cg == null) {
            Logger.error("[-] Call graph is empty, cannot perform path tracing!");
            return Collections.emptyList();
        }

        List<CallChain> allChains = new ArrayList<>();

        // 1. Map sensitive statements with BODY_HIT to their containing functions (Sink Functions)
        Set<HiFunction> sinkFunctions = new HashSet<>();
        for (Stmt stmt : sinkStmts) {
            HiFunction func = safeGetHiFunction(stmt);
            if (func != null) {
                sinkFunctions.add(func);
            }
        }

        // 2. Perform depth-first reverse traversal (DFS) for each Sink function
        for (HiFunction sinkFunc : sinkFunctions) {
            List<HiFunction> currentPath = new ArrayList<>();
            currentPath.add(sinkFunc);

            // Record visited nodes to prevent infinite loops
            Set<HiFunction> visited = new HashSet<>();
            visited.add(sinkFunc);

            traceBackwards(cg, sinkFunc, currentPath, allChains, visited);
        }

        return allChains;
    }

    // ======================================================
    // Per-stmt attribution: each sink Stmt gets its own chain objects
    // ======================================================

    /**
     * Builds a mapping from each sink Stmt to its containing HiFunction.
     * This is used by extractPrivacyCallChainsWithStmtAttribution to group
     * sink statements by function for efficient DFS traversal.
     *
     * @param sinkStmts Set of sink statements
     * @return Map from Stmt to its containing HiFunction
     */
    public static Map<Stmt, HiFunction> buildSinkToFunctionMap(Set<Stmt> sinkStmts) {
        Map<Stmt, HiFunction> map = new LinkedHashMap<>();
        for (Stmt stmt : sinkStmts) {
            HiFunction func = safeGetHiFunction(stmt);
            if (func != null) {
                map.put(stmt, func);
            }
        }
        return map;
    }

    /**
     * Extracts call chains with per-stmt attribution.
     *
     * Unlike {@link #extractPrivacyCallChains}, which collapses all sink statements
     * in the same function into a single set of chains, this method creates a
     * separate CallChain object for each sink Stmt within each function. This
     * enables downstream code to attribute chains to specific API call sites
     * (i.e., specific apiUsageIndex values) even when multiple API invocations
     * reside in the same function.
     *
     * The algorithm:
     * 1. Group sink Stmts by their containing HiFunction
     * 2. For each function, perform reverse DFS to find all call paths from entry to that function
     * 3. For each discovered path, create a CallChain per sink Stmt in that function,
     *    with the sinkStmt field populated
     *
     * @param hiFile              Parsed HiFile
     * @param cg                  Pre-built CallGraph
     * @param sinkStmts           Set of sink statements
     * @param sinkToFunctionMap   Pre-computed mapping from Stmt to its containing HiFunction
     *                           (can be built via {@link #buildSinkToFunctionMap})
     * @return List of CallChain objects, each with sinkStmt populated for per-call-site attribution
     */
    public static List<CallChain> extractPrivacyCallChainsWithStmtAttribution(
            HiFile hiFile,
            CallGraph cg,
            Set<Stmt> sinkStmts,
            Map<Stmt, HiFunction> sinkToFunctionMap
    ) {
        if (cg == null) {
            Logger.error("[-] Call graph is empty, cannot perform path tracing!");
            return Collections.emptyList();
        }

        if (sinkStmts == null || sinkStmts.isEmpty()) {
            return Collections.emptyList();
        }

        List<CallChain> allChains = new ArrayList<>();

        // 1. Group sink Stmts by their containing function
        Map<HiFunction, List<Stmt>> functionToSinks = new LinkedHashMap<>();
        for (Stmt stmt : sinkStmts) {
            HiFunction func = (sinkToFunctionMap != null) ? sinkToFunctionMap.get(stmt) : null;
            if (func == null) {
                func = safeGetHiFunction(stmt);
            }
            if (func != null) {
                functionToSinks.computeIfAbsent(func, k -> new ArrayList<>()).add(stmt);
            }
        }

        // 2. For each sink function, trace back to find all entry-to-sink paths
        for (Map.Entry<HiFunction, List<Stmt>> entry : functionToSinks.entrySet()) {
            HiFunction sinkFunc = entry.getKey();
            List<Stmt> stmtsInFunc = entry.getValue();

            List<HiFunction> currentPath = new ArrayList<>();
            currentPath.add(sinkFunc);

            Set<HiFunction> visited = new HashSet<>();
            visited.add(sinkFunc);

            List<CallChain> funcChains = new ArrayList<>();
            traceBackwards(cg, sinkFunc, currentPath, funcChains, visited);

            // 3. Attribute each discovered chain to every sink Stmt in this function.
            // All sink Stmts in the same function share the same set of call paths
            // from entry to that function, but each gets its own CallChain object
            // so they can be independently associated with specific apiUsageIndex values.
            for (CallChain chain : funcChains) {
                for (Stmt sinkStmt : stmtsInFunc) {
                    CallChain attributed = new CallChain();
                    attributed.rootNode = chain.rootNode;
                    attributed.sinkNode = chain.sinkNode;
                    attributed.path = chain.path; // Shared reference is safe (list is not mutated after this point)
                    attributed.sinkStmt = sinkStmt;
                    allChains.add(attributed);
                }
            }
        }

        Logger.log("[*] CallGraphExplorer: extracted " + allChains.size()
                + " per-stmt attributed chains from " + sinkStmts.size() + " sink stmts"
                + " across " + functionToSinks.size() + " functions");

        return allChains;
    }

    // ======================================================
    // DFS Reverse Traversal Logic
    // ======================================================
    private static void traceBackwards(CallGraph cg, HiFunction current, List<HiFunction> currentPath, List<CallChain> allChains, Set<HiFunction> visited) {
        Set<HiFunction> callers = cg.getCallersByCallee(current);

        // Recursion termination condition 1: if no callers, reached the outermost entry of business logic (Root)
        if (callers == null || callers.isEmpty()) {
            saveChain(currentPath, current, allChains);
            return;
        }

        boolean isAllVisited = true;
        for (HiFunction caller : callers) {
            if (!visited.contains(caller)) {
                isAllVisited = false;
                visited.add(caller);
                currentPath.add(caller);

                // Recursively go up one level
                traceBackwards(cg, caller, currentPath, allChains, visited);

                // Backtrack state for traversing other branches
                currentPath.remove(currentPath.size() - 1);
                visited.remove(caller);
            }
        }

        // Recursion termination condition 2: if all callers have been visited (circular call/recursion detected)
        // Truncate here and save as a valid chain to prevent DFS infinite loop
        if (isAllVisited && !callers.isEmpty()) {
            saveChain(currentPath, current, allChains);
        }
    }

    // ======================================================
    // Helper Methods
    // ======================================================
    private static void saveChain(List<HiFunction> currentPath, HiFunction currentRoot, List<CallChain> allChains) {
        CallChain chain = new CallChain();

        // Since we traverse in reverse, the first element of currentPath is actually the target Sink
        chain.sinkNode = currentPath.get(0);
        chain.rootNode = currentRoot;

        // Reverse path to conform to forward reading convention: Root -> [intermediate nodes] -> Sink
        List<HiFunction> reversePath = new ArrayList<>(currentPath);
        Collections.reverse(reversePath);
        chain.path = reversePath;

        allChains.add(chain);
    }

    private static HiFunction safeGetHiFunction(Stmt stmt) {
        try {
            return stmt.getHiFunction();
        } catch (Throwable t) {
            return null;
        }
    }
}
