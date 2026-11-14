package Firewall;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import Firewall.FirewallDecision.Action;

/**
 * Stores the ordered list of firewall rules and the default policy.
 *
 * Evaluation order: rules are checked in the order they were added
 * (top to bottom in rules.conf). The first matching rule wins.
 *
 * CopyOnWriteArrayList makes the list safe to read from many client
 * threads at once, even if rules are added or removed at runtime.
 */
public class RuleManager {

    private final List<FirewallRule> rules = new CopyOnWriteArrayList<>();
    private volatile Action defaultPolicy = Action.ALLOW;

    public void addRule(FirewallRule rule) {
        for (FirewallRule existing : rules) {
            if (existing.getId() == rule.getId()) {
                throw new IllegalArgumentException("Duplicate rule id: " + rule.getId());
            }
        }
        rules.add(rule);
    }

    public boolean removeRule(int id) {
        return rules.removeIf(r -> r.getId() == id);
    }

    public FirewallRule getRule(int id) {
        for (FirewallRule r : rules) {
            if (r.getId() == id) return r;
        }
        return null;
    }

    /** Read-only snapshot in evaluation order. */
    public List<FirewallRule> getRules() {
        return Collections.unmodifiableList(new ArrayList<>(rules));
    }

    public Action getDefaultPolicy()            { return defaultPolicy; }
    public void setDefaultPolicy(Action policy) { this.defaultPolicy = policy; }

    /**
     * Loads rules from a config file. Format (one rule per line):
     *   id | type | condition | action | enabled
     * plus an optional "default = ALLOW|BLOCK" line.
     * Lines starting with # and blank lines are ignored.
     */
    public static RuleManager loadFromFile(Path file) throws IOException {
        RuleManager manager = new RuleManager();
        int lineNo = 0;
        try (BufferedReader in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = in.readLine()) != null) {
                lineNo++;
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                try {
                    if (line.toLowerCase().startsWith("default")) {
                        String value = line.substring(line.indexOf('=') + 1).trim();
                        manager.setDefaultPolicy(Action.valueOf(value.toUpperCase()));
                        continue;
                    }
                    String[] parts = line.split("\\|");
                    if (parts.length != 5) {
                        throw new IllegalArgumentException("expected 5 fields separated by '|'");
                    }
                    int id = Integer.parseInt(parts[0].trim());
                    FirewallRule.Type type = FirewallRule.Type.valueOf(parts[1].trim().toUpperCase());
                    String condition = parts[2].trim();
                    Action action = Action.valueOf(parts[3].trim().toUpperCase());
                    boolean enabled = Boolean.parseBoolean(parts[4].trim());
                    manager.addRule(new FirewallRule(id, type, condition, action, enabled));
                } catch (IllegalArgumentException | StringIndexOutOfBoundsException e) {
                    // NumberFormatException is a subclass of IllegalArgumentException
                    throw new IOException(file + " line " + lineNo + ": " + e.getMessage()
                            + "  ->  \"" + line + "\"", e);
                }
            }
        }
        return manager;
    }

    /** Built-in rules used when no rules.conf file is found. */
    public static RuleManager defaults() {
        RuleManager m = new RuleManager();
        m.setDefaultPolicy(Action.ALLOW);
        m.addRule(new FirewallRule(1, FirewallRule.Type.KEYWORD, "BLOCKED", Action.BLOCK, true));
        m.addRule(new FirewallRule(2, FirewallRule.Type.IP, "192.168.1.20", Action.BLOCK, true));
        m.addRule(new FirewallRule(3, FirewallRule.Type.IP, "127.0.0.1", Action.ALLOW, true));
        return m;
    }
}
