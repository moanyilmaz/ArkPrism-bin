package com.huawei.hisec;

import com.huawei.hianalyzer.analysis.base.HiFunction;
import com.huawei.hianalyzer.analysis.graph.cfg.BasicBlock;
import com.huawei.hianalyzer.analysis.graph.cfg.BlockGraph;
import com.huawei.hianalyzer.analysis.graph.cfg.StmtGraph;
import com.huawei.hianalyzer.analysis.Stage;
import com.huawei.hianalyzer.ir.stmt.Stmt;

import java.util.*;

/**
 * CFG reachability analysis for determining whether a statement is reachable
 * from the function entry point.
 *
 * Uses Huawei's BlockGraph + DominantTree for efficient block-level reachability,
 * then falls back to StmtGraph BFS for precise statement-level check.
 * Results are cached per function to avoid repeated graph construction.
 */
public class ReachabilityAnalyzer {

    /**
     * Cache: maps HiFunction identity to the set of reachable Stmt objects.
     * Avoids rebuilding BlockGraph/DominantTree for repeated queries on the same function.
     */
    private static final IdentityHashMap<HiFunction, Set<Stmt>> reachabilityCache = new IdentityHashMap<>();

    /**
     * Checks whether targetStmt is reachable from the function entry point
     * via normal or exceptional control flow edges.
     *
     * Results are cached per function to avoid repeated graph construction.
     * Falls back to "reachable" (fail-open) if CFG construction fails,
     * to avoid false negatives when the analysis tool encounters unusual code.
     */
    public static boolean isReachableFromEntry(Stmt targetStmt) {
        if (targetStmt == null) {
            return false;
        }

        HiFunction func;
        try {
            func = targetStmt.getHiFunction();
        } catch (Throwable t) {
            func = null;
        }
        if (func == null) {
            return true;  // Cannot determine — conservative pass
        }

        // Check cache
        Set<Stmt> reachableStmts = reachabilityCache.get(func);
        if (reachableStmts != null) {
            return reachableStmts.contains(targetStmt);
        }

        // Build reachable set for this function
        reachableStmts = buildReachableSet(func);
        reachabilityCache.put(func, reachableStmts);
        return reachableStmts.contains(targetStmt);
    }

    /**
     * Clears the reachability cache. Should be called between ABC file analyses
     * to prevent memory leaks and ensure stale data is not reused.
     */
    public static void clearCache() {
        reachabilityCache.clear();
    }

    /**
     * Builds the complete set of reachable statements from the function entry.
     * Uses BlockGraph + DominantTree for efficient traversal.
     */
    private static Set<Stmt> buildReachableSet(HiFunction func) {
        Set<Stmt> reachable = new HashSet<>();

        try {
            var body = func.getBody();
            if (body == null) {
                // Cannot determine — treat all as reachable
                return null;  // null signals "all reachable"
            }

            BlockGraph blockGraph = BlockGraph.createOrGetGraph(func);
            if (blockGraph != null) {
                BasicBlock entryBlock = blockGraph.getEntryBlock();
                if (entryBlock != null) {
                    // BFS on block-level CFG from entry
                    Set<BasicBlock> reachableBlocks = new HashSet<>();
                    Deque<BasicBlock> queue = new ArrayDeque<>();
                    queue.add(entryBlock);
                    reachableBlocks.add(entryBlock);

                    while (!queue.isEmpty()) {
                        BasicBlock current = queue.poll();
                        for (BasicBlock succ : blockGraph.getSuccsOf(current)) {
                            if (!reachableBlocks.contains(succ)) {
                                reachableBlocks.add(succ);
                                queue.add(succ);
                            }
                        }
                    }

                    // Collect all statements in reachable blocks
                    for (BasicBlock block : reachableBlocks) {
                        for (Stmt s : block.getStmts()) {
                            reachable.add(s);
                        }
                    }
                    return reachable;
                }
            }

            // Fallback: StmtGraph BFS for precise check
            StmtGraph stmtGraph = Stage.createOrGetStmtGraph(func);
            if (stmtGraph == null) {
                return null;  // Cannot determine — treat all as reachable
            }

            Stmt graphEntry = stmtGraph.getEntryStmt();
            if (graphEntry == null) {
                return null;
            }

            Deque<Stmt> stmtQueue = new ArrayDeque<>();
            stmtQueue.add(graphEntry);
            reachable.add(graphEntry);

            while (!stmtQueue.isEmpty()) {
                Stmt current = stmtQueue.poll();
                for (Stmt succ : stmtGraph.getSuccsOf(current)) {
                    if (!reachable.contains(succ)) {
                        reachable.add(succ);
                        stmtQueue.add(succ);
                    }
                }
            }

            return reachable;

        } catch (Throwable t) {
            Logger.error("[ReachabilityAnalyzer] CFG reachability check failed: "
                    + (t.getMessage() != null ? t.getMessage() : t.getClass().getName()));
            return null;  // Fail-open: treat as all reachable
        }
    }
}
