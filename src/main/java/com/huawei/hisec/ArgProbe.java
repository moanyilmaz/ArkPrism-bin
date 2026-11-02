package com.huawei.hisec;

import com.huawei.hianalyzer.analysis.Stage;
import com.huawei.hianalyzer.analysis.base.HiFile;
import com.huawei.hianalyzer.analysis.base.HiFunction;
import com.huawei.hianalyzer.frontend.metainterface.SourceLang;
import com.huawei.hianalyzer.ir.stmt.CallStmt;
import com.huawei.hianalyzer.ir.stmt.Stmt;
import com.huawei.hianalyzer.ir.stmt.FieldAssignStmt;
import com.huawei.hianalyzer.ir.value.Value;
import com.huawei.hianalyzer.ir.value.constant.*;
import com.huawei.hianalyzer.ir.Body;

import java.io.File;
import java.util.*;

/**
 * Probe to inspect argument values for sensor.on/once and geoLocationManager.on calls.
 * Goal: understand how enum arguments are represented in the IR.
 */
public class ArgProbe {

    @SuppressWarnings("unchecked")
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

        Map<Stmt, String> stmtApiMap = hiFile.getAllStmtApiNameMap();

        for (Map.Entry<Stmt, String> entry : stmtApiMap.entrySet()) {
            String apiName = entry.getValue();
            if (apiName == null) continue;
            if (!apiName.contains("sensor.on") && !apiName.contains("sensor.once")
                && !apiName.contains("geoLocationManager.on")) {
                continue;
            }

            Stmt stmt = entry.getKey();
            System.out.println("\n=== API: " + apiName + " ===");
            System.out.println("  Stmt: " + stmt);

            if (stmt instanceof CallStmt) {
                CallStmt callStmt = (CallStmt) stmt;
                try {
                    var callExpr = callStmt.getCallExpr();
                    if (callExpr != null) {
                        var argList = callExpr.getArgList();
                        if (argList != null) {
                            System.out.println("  Arg count: " + argList.size());
                            for (int i = 0; i < argList.size(); i++) {
                                Object arg = argList.get(i);
                                System.out.println("    Arg[" + i + "]: " + arg);
                                System.out.println("    Arg[" + i + "].class: " + (arg == null ? "null" : arg.getClass().getName()));
                                if (arg instanceof StringConstant) {
                                    System.out.println("    Arg[" + i + "].value: " + ((StringConstant) arg).getValue());
                                } else if (arg instanceof IntConstant) {
                                    System.out.println("    Arg[" + i + "].value: " + ((IntConstant) arg).getValue());
                                } else if (arg instanceof com.huawei.hianalyzer.ir.value.Local) {
                                    com.huawei.hianalyzer.ir.value.Local local = (com.huawei.hianalyzer.ir.value.Local) arg;
                                    System.out.println("    Arg[" + i + "].name: " + local.getName());
                                    System.out.println("    Arg[" + i + "].type: " + local.getType());
                                }
                            }
                        }
                    }
                } catch (Throwable t) {
                    System.out.println("  Error inspecting args: " + t.getMessage());
                }
            }

            // Also look at the function body to find where the first arg is defined
            HiFunction func = null;
            try {
                func = com.huawei.hisec.ScannerUtils.safeGetHiFunction(stmt);
            } catch (Throwable ignored) {}
            if (func != null) {
                String funcName = func.getName();
                System.out.println("  Function: " + funcName);

                // Search backward in the function body for assignments to the first arg variable
                try {
                    Body body = func.getBody();
                    if (body != null) {
                        var stmts = body.getStmts();
                        if (stmts != null) {
                            // Find the index of current stmt
                            int stmtIdx = -1;
                            for (int i = 0; i < stmts.size(); i++) {
                                if (stmts.get(i) == stmt) {
                                    stmtIdx = i;
                                    break;
                                }
                            }
                            if (stmtIdx >= 0) {
                                // Look at 10 statements before the call
                                int start = Math.max(0, stmtIdx - 10);
                                System.out.println("  Preceding statements (idx " + start + " to " + (stmtIdx-1) + "):");
                                for (int i = start; i < stmtIdx; i++) {
                                    System.out.println("    [" + i + "] " + stmts.get(i));
                                }
                            }
                        }
                    }
                } catch (Throwable t) {
                    System.out.println("  Error reading body: " + t.getMessage());
                }
            }
        }

        // Also check geoLocationManager.on
        System.out.println("\n\n=== Checking geoLocationManager.on in FIELD map ===");
        Map<Stmt, String> fieldMap = hiFile.getAllStmtFieldNameMap();
        for (Map.Entry<Stmt, String> entry : fieldMap.entrySet()) {
            String name = entry.getValue();
            if (name != null && name.contains("geoLocationManager.on")) {
                System.out.println("  Field: " + name);
                System.out.println("  Stmt: " + entry.getKey());
            }
        }
    }
}
