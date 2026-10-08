package com.huawei.hisec;

import com.huawei.hianalyzer.analysis.Stage;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.ir.stmt.Stmt;
import com.huawei.hianalyzer.frontend.metainterface.SourceLang;

import java.io.File;
import java.util.*;

public class FieldMapProbe {
    public static void main(String[] args) throws Exception {
        File hapDir = new File(args[0]);
        File abcFile = new File(hapDir, "ets/modules.abc");
        if (!abcFile.exists()) {
            System.out.println("ABC not found: " + abcFile);
            return;
        }

        HiFile hiFile = Stage.createHiFile(abcFile.getAbsolutePath(), SourceLang.ARKTSV1);
        if (hiFile == null) {
            System.out.println("Failed to load HiFile");
            return;
        }

        Map<Stmt, String> fieldMap = hiFile.getAllStmtFieldNameMap();
        System.out.println("=== Field map entries containing 'start' ===");
        int count = 0;
        for (Map.Entry<Stmt, String> entry : fieldMap.entrySet()) {
            String name = entry.getValue();
            if (name != null && name.toLowerCase().contains("start")) {
                System.out.println("  Field: " + name);
                System.out.println("  Stmt: " + entry.getKey());
                System.out.println();
                count++;
            }
        }
        System.out.println("Total 'start' field entries: " + count);

        // Also check API map
        Map<Stmt, String> apiMap = hiFile.getAllStmtApiNameMap();
        System.out.println("\n=== API map entries containing 'start' ===");
        count = 0;
        for (Map.Entry<Stmt, String> entry : apiMap.entrySet()) {
            String name = entry.getValue();
            if (name != null && name.toLowerCase().contains("start")) {
                System.out.println("  API: " + name);
                System.out.println("  Stmt: " + entry.getKey());
                System.out.println();
                count++;
            }
        }
        System.out.println("Total 'start' API entries: " + count);

        // Check for 'osFullName' too
        System.out.println("\n=== Field map entries containing 'osFullName' ===");
        count = 0;
        for (Map.Entry<Stmt, String> entry : fieldMap.entrySet()) {
            String name = entry.getValue();
            if (name != null && name.contains("osFullName")) {
                System.out.println("  Field: " + name);
                System.out.println("  Stmt: " + entry.getKey());
                System.out.println();
                count++;
            }
        }
        System.out.println("Total 'osFullName' field entries: " + count);
    }
}
