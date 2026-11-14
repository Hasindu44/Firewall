package Firewall;

/**
 * The result of evaluating a request: ALLOW or BLOCK, plus the reason
 and the rule that produced it (or null if the default policy applied).
 */
public class FirewallDecision {

    public enum Action { ALLOW, BLOCK }

    private final Action action;
    private final String reason;
    private final Integer ruleId; // null when the default policy decided

    public FirewallDecision(Action action, String reason, Integer ruleId) {
        this.action = action;
        this.reason = reason;
        this.ruleId = ruleId;
    }

    public Action getAction()   { return action; }
    public String getReason()   { return reason; }
    public Integer getRuleId()  { return ruleId; }
    public boolean isAllowed()  { return action == Action.ALLOW; }

    @Override
    public String toString() {
        String source = (ruleId == null) ? "default policy" : "rule " + ruleId;
        return action + " (" + source + "): " + reason;
    }
}
