package Firewall;

import Firewall.FirewallDecision.Action;

/**
 * A single firewall rule, e.g. "BLOCK requests from 192.168.1.20"
 * or "BLOCK messages containing BLOCKED".
 */
public class FirewallRule {

    public enum Type { IP, KEYWORD }

    private final int id;
    private final Type type;
    private final String condition;
    private final Action action;
    private volatile boolean enabled; // volatile: may be toggled while server threads read it

    public FirewallRule(int id, Type type, String condition, Action action, boolean enabled) {
        if (condition == null || condition.trim().isEmpty()) {
            throw new IllegalArgumentException("Rule " + id + ": condition must not be empty");
        }
        this.id = id;
        this.type = type;
        this.condition = condition.trim();
        this.action = action;
        this.enabled = enabled;
    }

    /**
     * Returns true if this rule applies to the given request.
     * A disabled rule never matches.
     *
     * @param clientIP the address observed by the server
     * @param message  the client's message, or null when checking a new connection
     */
    public boolean matches(String clientIP, String message) {
        if (!enabled) {
            return false;
        }
        switch (type) {
            case IP:
                return clientIP != null && clientIP.equals(condition);
            case KEYWORD:
                return message != null
                        && message.toLowerCase().contains(condition.toLowerCase());
            default:
                return false;
        }
    }

    /** Human-readable explanation used in logs and client responses. */
    public String describe() {
        if (type == Type.IP) {
            return "Client IP " + condition + (action == Action.BLOCK ? " is blocked" : " is permitted");
        }
        return "Message contains keyword '" + condition + "'"
                + (action == Action.BLOCK ? " (prohibited)" : " (permitted)");
    }

    public int getId()           { return id; }
    public Type getType()        { return type; }
    public String getCondition() { return condition; }
    public Action getAction()    { return action; }
    public boolean isEnabled()   { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    @Override
    public String toString() {
        return String.format("%d | %-7s | %-15s | %-5s | %s",
                id, type, condition, action, enabled ? "enabled" : "disabled");
    }
}
