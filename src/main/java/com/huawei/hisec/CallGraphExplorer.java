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