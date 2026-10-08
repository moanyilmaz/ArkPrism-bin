package com.huawei.hisec;

import com.huawei.hianalyzer.analysis.Stage;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.base.HiFunction;
import com.huawei.hianalyzer.analysis.base.HiClass;
import com.huawei.hianalyzer.analysis.base.HiField;
import com.huawei.hianalyzer.analysis.foreign.ForeignClass;
import com.huawei.hianalyzer.analysis.foreign.ForeignFunction;
import com.huawei.hianalyzer.analysis.foreign.ForeignField;
import com.huawei.hianalyzer.ir.stmt.Stmt;
import com.huawei.hianalyzer.ir.stmt.CallStmt;
import com.huawei.hianalyzer.ir.stmt.FieldAssignStmt;
import com.huawei.hianalyzer.frontend.metainterface.IMetaFile;
import com.huawei.hianalyzer.converter.IDataConverter;

import java.io.File;
import java.util.*;

/**
 * Probe to inspect what HiAnalyzer directly provides:
 * - getAllStmtApiNameMap(): Stmt -> full API name
 * - getAllStmtFieldNameMap(): Stmt -> full field name
 * - getFullApiNameByStmt(): single call resolution
 * - HiFunction.getBody(): IR body with all statements
 */
public class HiAnalyzerProbe {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: HiAnalyzerProbe <hap_dir>");
            return;
        }

        File hapDir = new File(args[0]);
        File abcFile = new File(hapDir, "ets/modules.abc");
        if (!abcFile.exists()) {
            // Try finding abc files
            System.out.println("Looking for .abc files in: " + hapDir);
            findAbcFiles(hapDir);
            return;
        }

        System.out.println("=== HiAnalyzer Probe ===");
        System.out.println("ABC file: " + abcFile.getAbsolutePath());

        // Use Stage to load the ABC file
        HiFile hiFile = Stage.createHiFile(abcFile.getAbsolutePath(),
                com.huawei.hianalyzer.frontend.metainterface.SourceLang.ARKTSV1);

        if (hiFile == null) {
            System.out.println("Failed to load HiFile (V1 parser returned null)");
            return;
        }

        System.out.println("\n=== HiFile Basic Info ===");
        System.out.println("Path: " + hiFile.getPath());
        System.out.println("HiClasses: " + hiFile.getHiClasses().size());
        System.out.println("HiFunctions: " + hiFile.getHiFunctions().size());
        System.out.println("HiFields: " + hiFile.getHiFields().size());
        System.out.println("ForeignClasses: " + hiFile.getForeignClasses().size());
        System.out.println("ForeignFunctions: " + hiFile.getForeignFunctions().size());
        System.out.println("ForeignFields: " + hiFile.getForeignFields().size());

        // 1. getAllStmtApiNameMap - THE KEY API
        System.out.println("\n=== getAllStmtApiNameMap ===");
        Map<Stmt, String> stmtApiMap = hiFile.getAllStmtApiNameMap();
        if (stmtApiMap != null) {
            System.out.println("Total API call statements: " + stmtApiMap.size());
            int count = 0;
            for (Map.Entry<Stmt, String> entry : stmtApiMap.entrySet()) {
                String apiName = entry.getValue();
                String stmtText = entry.getKey() != null ? entry.getKey().toString() : "null";
                // Only show unique API names
                System.out.println("  [" + count + "] API=" + apiName);
                System.out.println("       Stmt=" + stmtText);
                count++;
                if (count >= 200) {
                    System.out.println("  ... (truncated, total=" + stmtApiMap.size() + ")");
                    break;
                }
            }
        } else {
            System.out.println("getAllStmtApiNameMap returned null!");
        }

        // 2. getAllStmtFieldNameMap
        System.out.println("\n=== getAllStmtFieldNameMap ===");
        Map<Stmt, String> stmtFieldMap = hiFile.getAllStmtFieldNameMap();
        if (stmtFieldMap != null) {
            System.out.println("Total field access statements: " + stmtFieldMap.size());
            int count = 0;
            for (Map.Entry<Stmt, String> entry : stmtFieldMap.entrySet()) {
                String fieldName = entry.getValue();
                String stmtText = entry.getKey() != null ? entry.getKey().toString() : "null";
                System.out.println("  [" + count + "] Field=" + fieldName);
                System.out.println("       Stmt=" + stmtText);
                count++;
                if (count >= 200) {
                    System.out.println("  ... (truncated, total=" + stmtFieldMap.size() + ")");
                    break;
                }
            }
        } else {
            System.out.println("getAllStmtFieldNameMap returned null!");
        }

        // 3. List all unique API names (deduplicated)
        System.out.println("\n=== Unique API Names (from stmtApiMap) ===");
        if (stmtApiMap != null) {
            Set<String> uniqueApis = new TreeSet<>(stmtApiMap.values());
            System.out.println("Unique API count: " + uniqueApis.size());
            for (String api : uniqueApis) {
                System.out.println("  " + api);
            }
        }

        // 4. List all unique field names
        System.out.println("\n=== Unique Field Names (from stmtFieldMap) ===");
        if (stmtFieldMap != null) {
            Set<String> uniqueFields = new TreeSet<>(stmtFieldMap.values());
            System.out.println("Unique field count: " + uniqueFields.size());
            for (String field : uniqueFields) {
                System.out.println("  " + field);
            }
        }

        // 5. List all HiFunctions with their bodies
        System.out.println("\n=== HiFunctions Summary ===");
        for (HiFunction func : hiFile.getHiFunctions()) {
            String name = func.toString();
            var body = func.getNullableBody();
            int stmtCount = body != null ? body.getStmts().size() : 0;
            if (stmtCount > 0) {
                System.out.println("  " + name + " (stmts=" + stmtCount + ")");
            }
        }

        System.out.println("\n=== Done ===");
    }

    private static void findAbcFiles(File dir) {
        File[] children = dir.listFiles();
        if (children == null) return;
        for (File child : children) {
            if (child.isDirectory()) {
                findAbcFiles(child);
            } else if (child.getName().endsWith(".abc")) {
                System.out.println("  Found ABC: " + child.getAbsolutePath());
            }
        }
    }
}
