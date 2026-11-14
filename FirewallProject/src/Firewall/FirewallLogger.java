package Firewall;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;

/**
 * Records firewall decisions to the console and (optionally) a log file.
 *
 * Format:  2026-10-27 12:00:01 | 127.0.0.1 | ALLOW | reason | "message summary"
 *
 * Methods are synchronized so lines from different client threads
 * never interleave in the middle of an entry.
 */
public class FirewallLogger implements AutoCloseable {

    private static final DateTimeFormatter TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final int MAX_SUMMARY = 60;

    /** Messages that look like they carry secrets are never logged verbatim. */
    private static final Pattern SENSITIVE = Pattern.compile(
            "(?i)(password|passwd|pwd|secret|token|api[_-]?key)\\s*[:=]");

    private final BufferedWriter fileOut; // null = console only

    /** Receives every log entry (used by the GUI). action is ALLOW, BLOCK or INFO. */
    public interface Listener {
        void onEntry(String time, String clientIP, String action, String reason, String summary);
    }
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();
    public void addListener(Listener l) { listeners.add(l); }

    private void notifyListeners(String time, String ip, String action, String reason, String summary) {
        for (Listener l : listeners) {
            try { l.onEntry(time, ip, action, reason, summary); } catch (RuntimeException ignored) { }
        }
    }

    /** Console-only logger. */
    public FirewallLogger() {
        this.fileOut = null;
    }

    /** Logs to console and appends to the given file (parent folders are created). */
    public FirewallLogger(Path logFile) throws IOException {
        if (logFile.getParent() != null) {
            Files.createDirectories(logFile.getParent());
        }
        this.fileOut = Files.newBufferedWriter(logFile, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    public synchronized void logDecision(String clientIP, FirewallDecision decision, String message) {
        String time = LocalDateTime.now().format(TIME);
        String summary = message == null ? "" : summarize(message);
        notifyListeners(time, clientIP, decision.getAction().name(), decision.getReason(), summary);
        String entry = String.format("%s | %-15s | %-5s | %s%s",
                time,
                clientIP,
                decision.getAction(),
                decision.getReason(),
                message == null ? "" : " | \"" + summarize(message) + "\"");
        write(entry);
    }

    /** For non-decision events such as server start, disconnects and errors. */
    public synchronized void logEvent(String clientIP, String event) {
        String time = LocalDateTime.now().format(TIME);
        notifyListeners(time, clientIP, "INFO", event, "");
        write(String.format("%s | %-15s | %-5s | %s", time, clientIP, "INFO", event));
    }

    /** Shortens long messages, redacts likely secrets, and removes control characters. */
    static String summarize(String message) {
        if (SENSITIVE.matcher(message).find()) {
            return "[redacted: possible credentials]";
        }
        String clean = message.replaceAll("\\p{Cntrl}", " ");
        return clean.length() <= MAX_SUMMARY ? clean : clean.substring(0, MAX_SUMMARY) + "...";
    }

    private void write(String entry) {
        System.out.println(entry);
        if (fileOut != null) {
            try {
                fileOut.write(entry);
                fileOut.newLine();
                fileOut.flush();
            } catch (IOException e) {
                System.err.println("Could not write to log file: " + e.getMessage());
            }
        }
    }

    @Override
    public synchronized void close() throws IOException {
        if (fileOut != null) fileOut.close();
    }
}
