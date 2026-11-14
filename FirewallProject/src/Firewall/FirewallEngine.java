package Firewall;

import Firewall.FirewallDecision.Action;

/**
 * Decides whether a request is allowed or blocked.
 *
 * Policy (explicit, so decisions are predictable):
  1. Rules are checked in order; the FIRST matching enabled rule decides.
 2. If no rule matches, the RuleManager's default policy decides.
 
 wo checkpoints are used by the server:
   - checkConnection(ip)       : when a client first connects (IP rules only)
   - checkMessage(ip, message) : for every message (all rules)
 */
public class FirewallEngine {

    private final RuleManager ruleManager;

    public FirewallEngine(RuleManager ruleManager) {
        this.ruleManager = ruleManager;
    }

    /** Connection-time check. No message exists yet, so only IP rules can match. */
    public FirewallDecision checkConnection(String clientIP) {
        return evaluate(clientIP, null);
    }

    /** Message-time check against every rule. */
    public FirewallDecision checkMessage(String clientIP, String message) {
        return evaluate(clientIP, message);
    }

    private FirewallDecision evaluate(String clientIP, String message) {
        for (FirewallRule rule : ruleManager.getRules()) {
            if (rule.matches(clientIP, message)) {
                return new FirewallDecision(rule.getAction(), rule.describe(), rule.getId());
            }
        }
        Action policy = ruleManager.getDefaultPolicy();
        return new FirewallDecision(policy, "No rule matched; default policy is " + policy, null);
    }

    public RuleManager getRuleManager() {
        return ruleManager;
    }
}
