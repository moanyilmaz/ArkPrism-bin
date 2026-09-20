package com.huawei.hisec;

import com.huawei.hianalyzer.analysis.Stage;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.base.HiFunction;
import com.huawei.hianalyzer.frontend.metainterface.SourceLang;
import com.huawei.hianalyzer.ir.stmt.Stmt;
import com.huawei.hianalyzer.ir.stmt.CallStmt;

import java.io.File;
import java.util.*;

/**
 * Probe to trace ResolvedNameInfo for specific API_MAP entries.
 */
public class IndirectCallProbe {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: IndirectCallProbe <hapDir> <keyword>");
            return;
        }
        String hapDir = args[0];
        String keyword = args[1].toLowerCase();

        List<File> abcFiles = new ArrayList<>();
        findAbcFiles(new File(hapDir), abcFiles);

        for (File abcFile : abcFiles) {
            HiFile hiFile = null;
            try {
                hiFile = Stage.createHiFile(abcFile.getAbsolutePath(), SourceLang.ARKTSV1);
            } catch (Throwable t) { continue; }
            if (hiFile == null) continue;

            Map<Stmt, String> apiMap = hiFile.getAllStmtApiNameMap();

            for (Map.Entry<Stmt, String> entry : apiMap.entrySet()) {
                String name = entry.getValue();
                if (name == null || !name.toLowerCase().contains(keyword)) continue;

                Stmt stmt = entry.getKey();
                System.out.println("\n=== API_MAP: " + name + " ===");
                System.out.println("Stmt: " + safe(stmt));

                // Parse resolved name using NamePathMatcher
                var info = NamePathMatcher.parseResolvedName(name);
                System.out.println("sourcePrefix: " + info.sourcePrefix);
                System.out.println("rootQualifier: " + info.rootQualifier);
                System.out.println("pathTokens: " + info.pathTokens);
                System.out.println("lastToken: " + info.lastToken);
                System.out.println("valid: " + info.valid);

                // Check imported SDK modules
                Set<String> imported = new HashSet<>();
                try {
                    for (var fc : hiFile.getForeignClasses()) {
                        String fromPath = fc.getFromPath();
                        if (fromPath != null && (fromPath.contains("@ohos:") || fromPath.contains("@kit:")
                                || fromPath.startsWith("@ohos.") || fromPath.startsWith("@kit."))) {
                            imported.add(fromPath.toLowerCase());
                        }
                    }
                } catch (Throwable t) {}
                try {
                    for (var ff : hiFile.getForeignFunctions()) {
                        String fromPath = ff.getFromPath();
                        if (fromPath != null && (fromPath.contains("@ohos:") || fromPath.contains("@kit:")
                                || fromPath.startsWith("@ohos.") || fromPath.startsWith("@kit."))) {
                            imported.add(fromPath.toLowerCase());
                        }
                    }
                } catch (Throwable t) {}
                try {
                    for (var ffield : hiFile.getForeignFields()) {
                        String fromPath = ffield.getFromPath();
                        if (fromPath != null && (fromPath.contains("@ohos:") || fromPath.contains("@kit:")
                                || fromPath.startsWith("@ohos.") || fromPath.startsWith("@kit."))) {
                            imported.add(fromPath.toLowerCase());
                        }
                    }
                } catch (Throwable t) {}
                System.out.println("\nAll imported SDK modules:");
                for (String s : imported) {
                    System.out.println("  " + s);
                }
                System.out.println("\nImported SDK modules containing 'photo':");
                for (String s : imported) {
                    if (s.contains("photo")) System.out.println("  " + s);
                }
            }
        }
        System.out.println("\n[DONE]");
    }

    static void findAbcFiles(File dir, List<File> result) {
        if (dir == null || !dir.exists()) return;
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isDirectory()) findAbcFiles(f, result);
            else if (f.getName().endsWith(".abc")) result.add(f);
        }
    }

    static String safe(Stmt stmt) {
        if (stmt == null) return "null";
        try { return stmt.toString(); } catch (Exception e) { return "err"; }
    }
}
