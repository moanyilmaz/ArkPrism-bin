package com.huawei.hisec;

import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.graph.callgraph.pta.andersen.Andersen;
import com.huawei.hianalyzer.dataflow.ifds.analysis.taint.AliasManager;
import com.huawei.hianalyzer.ir.stmt.Stmt;
import com.huawei.hianalyzer.ir.value.ArrayElement;
import com.huawei.hianalyzer.ir.value.reference.FieldRef;

import java.util.*;

/**
 * AliasAnalyzer
 *
 * Wraps Huawei's Andersen PTA (Points-To Analysis) and AliasManager to provide
 * field-level and array-level alias analysis.
 *
 * Usage:
 *   AliasAnalyzer analyzer = new AliasAnalyzer(hiFile);
 *   boolean same = analyzer.areFieldAliased(fieldRef1, fieldRef2);
 *   boolean same = analyzer.areArrayAliased(arr1, idx1, arr2, idx2);
 *
 * Note: Andersen analysis is expensive (computes points-to for entire call graph).
 * Construction is lazy — build only when needed.
 */
public class AliasAnalyzer {

    private final HiFile hiFile;
    private Andersen andersen;
    private AliasManager aliasManager;
    private boolean initialized = false;

    public AliasAnalyzer(HiFile hiFile) {
        this.hiFile = hiFile;
    }

    /**
     * Lazily initializes Andersen PTA and AliasManager.
     * Thread-safe with double-checked locking.
     */
    private void ensureInitialized() {
        if (!initialized) {
            synchronized (this) {
                if (!initialized) {
                    try {
                        // Andersen(HiFile, boolean) — second param enables/diables field sensitivity
                        this.andersen = new Andersen(hiFile, true);
                        this.aliasManager = new AliasManager(andersen);
                        this.initialized = true;
                        Logger.log("[AliasAnalyzer] Andersen PTA initialized with field sensitivity");
                    } catch (Throwable t) {
                        Logger.error("[AliasAnalyzer] Failed to initialize Andersen: " + t.getMessage());
                    }
                }
            }
        }
    }

    /**
     * Checks if two FieldRef expressions refer to the same memory location.
     * Uses Huawei's AliasManager.aliasEqual(FieldRef, FieldRef) internally.
     *
     * @return true if they are aliased, false otherwise.
     *         Returns false if analysis fails or is not initialized.
     */
    public boolean areFieldAliased(FieldRef ref1, FieldRef ref2) {
        if (ref1 == null || ref2 == null) {
            return false;
        }
        ensureInitialized();
        if (!initialized || aliasManager == null) {
            return false;
        }
        try {
            return aliasManager.aliasEqual(ref1, ref2);
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Checks if two ArrayElement accesses refer to the same memory location.
     * Uses Huawei's AliasManager.aliasEqual(ArrayElement, ArrayElement) internally.
     *
     * @return true if they are aliased, false otherwise.
     *         Returns false if analysis fails or is not initialized.
     */
    public boolean areArrayAliased(ArrayElement elem1, ArrayElement elem2) {
        if (elem1 == null || elem2 == null) {
            return false;
        }
        ensureInitialized();
        if (!initialized || aliasManager == null) {
            return false;
        }
        try {
            return aliasManager.aliasEqual(elem1, elem2);
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Gets all statements where the given Local variable may point to.
     * Uses Huawei's Andersen.getPointsToStmts(Local) internally.
     *
     * @return Set of Stmt objects (maybe empty if analysis unavailable).
     */
    public Set<Stmt> getPointsToStmts(com.huawei.hianalyzer.ir.value.Local local) {
        ensureInitialized();
        if (!initialized || andersen == null) {
            return Collections.emptySet();
        }
        try {
            return andersen.getPointsToStmts(local);
        } catch (Throwable t) {
            return Collections.emptySet();
        }
    }

    /**
     * Checks if two Local variables may point to the same object.
     * Uses Huawei's Andersen.comparePointers(Local, Local) internally.
     *
     * @return true if they may be aliased, false otherwise.
     */
    public boolean mayPointToSameObject(com.huawei.hianalyzer.ir.value.Local local1,
                                         com.huawei.hianalyzer.ir.value.Local local2) {
        ensureInitialized();
        if (!initialized || andersen == null) {
            return false;
        }
        try {
            return andersen.comparePointers(local1, local2);
        } catch (Throwable t) {
            return false;
        }
    }

    public boolean isInitialized() {
        return initialized;
    }
}