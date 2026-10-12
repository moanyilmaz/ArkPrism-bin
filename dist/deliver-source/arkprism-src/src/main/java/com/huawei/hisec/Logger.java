package com.huawei.hisec;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Centralized logging utility for ArkPrism.
 * Similar to Python's logging module, each line includes timestamp and level.
 *
 * Example output:
 *   2026-05-21 10:00:00.123 [INFO ] Starting ArkPrism analysis...
 *   2026-05-21 10:00:01.456 [ERROR] Input directory not found
 */
public class Logger {

    /**
     * Log level enumeration.
     */
    public enum Level {
        DEBUG("[DEBUG]"),
        INFO ("[INFO ]"),
        WARN ("[WARN ]"),
        ERROR("[ERROR]");

        private final String tag;

        Level(String tag) {
            this.tag = tag;
        }

        public String getTag() {
            return tag;
        }
    }

    private static PrintWriter writer;
    private static String logFilePath;
    private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
    private static boolean showTimestamp = true;
    private static boolean showLevel = true;

    /**
     * Initialize the logger with a log file path.
     *
     * @param logFile The file to write logs to
     * @throws IOException if the file cannot be created
     */
    public static void init(File logFile) throws IOException {
        if (logFile == null) {
            throw new IllegalArgumentException("Log file cannot be null");
        }

        // Ensure parent directory exists
        File parent = logFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        writer = new PrintWriter(new FileWriter(logFile), true);
        logFilePath = logFile.getAbsolutePath();
    }

    /**
     * Check if logging is initialized.
     */
    public static boolean isInitialized() {
        return writer != null;
    }

    /**
     * Get the current log file path.
     */
    public static String getLogFilePath() {
        return logFilePath;
    }

    /**
     * Enable or disable timestamp in log output.
     */
    public static void setShowTimestamp(boolean show) {
        showTimestamp = show;
    }

    /**
     * Enable or disable log level in output.
     */
    public static void setShowLevel(boolean show) {
        showLevel = show;
    }

    /**
     * Build formatted log line with timestamp and level.
     */
    private static String formatMessage(Level level, String message) {
        StringBuilder sb = new StringBuilder();

        if (showTimestamp) {
            sb.append(dateFormat.format(new Date())).append(" ");
        }

        if (showLevel && level != null) {
            sb.append(level.getTag()).append(" ");
        }

        sb.append(message);
        return sb.toString();
    }

    /**
     * Log a DEBUG message to both console and file.
     *
     * @param message The message to log
     */
    public static void debug(String message) {
        String formatted = formatMessage(Level.DEBUG, message);
        System.out.println(formatted);
        if (writer != null) {
            writer.println(formatted);
        }
    }

    /**
     * Log an INFO message to both console and file.
     *
     * @param message The message to log
     */
    public static void info(String message) {
        String formatted = formatMessage(Level.INFO, message);
        System.out.println(formatted);
        if (writer != null) {
            writer.println(formatted);
        }
    }

    /**
     * Log a WARN message to both console and file.
     *
     * @param message The message to log
     */
    public static void warn(String message) {
        String formatted = formatMessage(Level.WARN, message);
        System.out.println(formatted);
        if (writer != null) {
            writer.println(formatted);
        }
    }

    /**
     * Log an ERROR message to both console and file.
     *
     * @param message The message to log
     */
    public static void error(String message) {
        String formatted = formatMessage(Level.ERROR, message);
        System.err.println(formatted);
        if (writer != null) {
            writer.println(formatted);
        }
    }

    /**
     * Log a message (INFO level) to both console and file.
     * Alias for {@link #info(String)}.
     *
     * @param message The message to log
     */
    public static void log(String message) {
        info(message);
    }

    /**
     * Log a formatted message with custom level.
     *
     * @param level   Log level
     * @param message The message to log
     */
    public static void log(Level level, String message) {
        String formatted = formatMessage(level, message);
        if (level == Level.ERROR) {
            System.err.println(formatted);
        } else {
            System.out.println(formatted);
        }
        if (writer != null) {
            writer.println(formatted);
        }
    }

    /**
     * Log section separator.
     *
     * @param separator The separator character(s)
     * @param length    The length of the separator
     */
    public static void logSeparator(String separator, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(separator);
        }
        info(sb.toString());
    }

    /**
     * Close the logger and flush all pending writes.
     */
    public static void close() {
        if (writer != null) {
            writer.flush();
            writer.close();
            writer = null;
        }
    }

    /**
     * Generate a default log file name based on timestamp.
     *
     * @param outputDir The output directory
     * @return A File object for the log file
     */
    public static File generateLogFile(File outputDir) {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String logFileName = "arkprism_" + timestamp + ".log";
        return new File(outputDir, logFileName);
    }
}