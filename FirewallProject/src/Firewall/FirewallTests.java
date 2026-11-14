package Firewall;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import Firewall.FirewallDecision.Action;

/**
 * Simple tests for the firewall (no JUnit needed).
 * Run this class like a normal Java program.
 *
 * It tests:
 *  - message filtering (keywords)
 *  - IP filtering
 *  - rule order and the default policy
 *  - turning rules on and off
 *  - the logger
 *  - a real client talking to a real server
 */
public class FirewallTests {

    // Counters for the final result
    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        testMessageFiltering();
        testIpFiltering();
        testRulePriorityAndDefaults();
        testDisabledRule();
        testLoggerRedaction();
        testEndToEnd();

        System.out.println();
        System.out.println("Passed: " + passed + "   Failed: " + failed);

        // We must exit by hand, because the test servers are still running.
        if (failed > 0) {
            System.exit(1);
        } else {
            System.exit(0);
        }
    }

    // =========================================================
    // 1. Message filtering
    // =========================================================
    private static void testMessageFiltering() {
        section("Message filtering");
        FirewallEngine engine = new FirewallEngine(RuleManager.defaults());
        String ip = "10.0.0.5"; // this IP does not match any IP rule

        check("'Hello server' allowed",
                engine.checkMessage(ip, "Hello server").isAllowed());

        check("'Show my status' allowed",
                engine.checkMessage(ip, "Show my status").isAllowed());

        check("'...contains BLOCKED' blocked",
                !engine.checkMessage(ip, "This message contains BLOCKED").isAllowed());

        check("keyword match ignores upper/lower case",
                !engine.checkMessage(ip, "this is blocked too").isAllowed());

        check("'Please process my request' allowed",
                engine.checkMessage(ip, "Please process my request").isAllowed());
    }

    // =========================================================
    // 2. IP filtering
    // =========================================================
    private static void testIpFiltering() {
        section("IP filtering");
        FirewallEngine engine = new FirewallEngine(RuleManager.defaults());

        // 127.0.0.1 should be allowed by rule 3
        FirewallDecision local = engine.checkConnection("127.0.0.1");
        boolean localOk = local.isAllowed()
                && local.getRuleId() != null
                && local.getRuleId() == 3;
        check("127.0.0.1 allowed by rule 3", localOk);

        // 192.168.1.20 should be blocked by rule 2
        FirewallDecision bad = engine.checkConnection("192.168.1.20");
        boolean badOk = !bad.isAllowed()
                && bad.getRuleId() != null
                && bad.getRuleId() == 2;
        check("192.168.1.20 blocked by rule 2", badOk);

        // When connecting, keyword rules are not used, so no rule matches
        FirewallDecision other = engine.checkConnection("10.0.0.5");
        check("keyword rules ignored at connection time", other.getRuleId() == null);
    }

    // =========================================================
    // 3. Rule order and default policy
    // =========================================================
    private static void testRulePriorityAndDefaults() {
        section("Rule priority and default policy");
        FirewallEngine engine = new FirewallEngine(RuleManager.defaults());

        // Rule 1 (block keyword) comes before rule 3 (allow 127.0.0.1).
        // The first rule that matches wins, so the message is blocked.
        FirewallDecision d = engine.checkMessage("127.0.0.1", "BLOCKED please");
        boolean firstRuleWins = !d.isAllowed()
                && d.getRuleId() != null
                && d.getRuleId() == 1;
        check("earlier keyword BLOCK beats later IP ALLOW", firstRuleWins);

        // A strict firewall: block everything, except 127.0.0.1
        RuleManager strict = new RuleManager();
        strict.setDefaultPolicy(Action.BLOCK);
        strict.addRule(new FirewallRule(1, FirewallRule.Type.IP, "127.0.0.1", Action.ALLOW, true));
        FirewallEngine strictEngine = new FirewallEngine(strict);

        check("default BLOCK rejects unknown IP",
                !strictEngine.checkConnection("10.0.0.5").isAllowed());

        check("allowed IP passes under default BLOCK",
                strictEngine.checkConnection("127.0.0.1").isAllowed());

        // Adding a second rule with the same id (1) should cause an error
        boolean gotError = false;
        try {
            strict.addRule(new FirewallRule(1, FirewallRule.Type.IP, "1.2.3.4", Action.BLOCK, true));
        } catch (IllegalArgumentException e) {
            gotError = true;
        }
        check("duplicate rule id rejected", gotError);
    }

    // =========================================================
    // 4. Turning rules on and off
    // =========================================================
    private static void testDisabledRule() {
        section("Enabled / disabled rules");
        RuleManager rules = RuleManager.defaults();
        FirewallEngine engine = new FirewallEngine(rules);

        // Turn rule 1 off -> the keyword is no longer blocked
        rules.getRule(1).setEnabled(false);
        check("disabled keyword rule no longer blocks",
                engine.checkMessage("10.0.0.5", "BLOCKED").isAllowed());

        // Turn rule 1 on again -> the keyword is blocked again
        rules.getRule(1).setEnabled(true);
        check("re-enabled rule blocks again",
                !engine.checkMessage("10.0.0.5", "BLOCKED").isAllowed());
    }

    // =========================================================
    // 5. Logger
    // =========================================================
    private static void testLoggerRedaction() {
        section("Logger");

        String hidden = FirewallLogger.summarize("login password=hunter2");
        check("password is hidden", hidden.startsWith("[redacted"));

        String longText = makeText('x', 200);
        String shortened = FirewallLogger.summarize(longText);
        check("long messages are cut short", shortened.endsWith("..."));

        String normal = FirewallLogger.summarize("Hello");
        check("normal message unchanged", normal.equals("Hello"));
    }

    // =========================================================
    // 6. Real client and server over TCP
    // =========================================================
    private static void testEndToEnd() throws Exception {
        section("End-to-end over TCP");
        int port = 19806;
        int blockedPort = 19807;

        // Nothing is running yet, so connecting should fail
        check("connecting to a stopped server fails", !canConnect(port));

        // Start a normal server and talk to it
        startServer(port, RuleManager.defaults());
        String[] messages = {"Hello server", "This message contains BLOCKED", "QUIT"};
        List<String> replies = talkToServer(port, messages);

        check("greeting is ALLOW", replies.get(0).startsWith("ALLOW"));
        check("normal message ALLOW", replies.get(1).startsWith("ALLOW"));
        check("keyword message BLOCK", replies.get(2).startsWith("BLOCK"));
        check("QUIT acknowledged", replies.get(3).startsWith("ALLOW: Goodbye"));

        // Pretend we come from a blocked IP:
        // start a second server that blocks 127.0.0.1 (our own computer)
        RuleManager blockLocal = new RuleManager();
        blockLocal.addRule(new FirewallRule(1, FirewallRule.Type.IP, "127.0.0.1", Action.BLOCK, true));
        startServer(blockedPort, blockLocal);

        List<String> rejected = talkToServer(blockedPort, new String[0]);
        boolean wasRejected = rejected.size() == 1
                && rejected.get(0).startsWith("BLOCK: Connection rejected");
        check("blocked IP gets connection rejected", wasRejected);

        // Connect and then leave suddenly. The server must not crash.
        Socket quickSocket = new Socket("127.0.0.1", port);
        quickSocket.getInputStream().read();
        quickSocket.close();

        List<String> after = talkToServer(port, new String[] {"still alive?"});
        check("server survives sudden disconnect", after.size() == 2);

        // Several clients at the same time
        int numberOfClients = 5;
        ClientThread[] clients = new ClientThread[numberOfClients];

        for (int i = 0; i < numberOfClients; i++) {
            clients[i] = new ClientThread(port, i);
            clients[i].start();
        }

        int goodClients = 0;
        for (int i = 0; i < numberOfClients; i++) {
            clients[i].join(); // wait until this client is finished
            if (clients[i].success) {
                goodClients++;
            }
        }
        check(numberOfClients + " clients at the same time all get correct answers",
                goodClients == numberOfClients);
    }

    // =========================================================
    // Helper classes and methods for the TCP tests
    // =========================================================

    /** A thread that runs the server in the background. */
    private static class ServerThread extends Thread {
        private TCP_Server server;

        ServerThread(TCP_Server server) {
            this.server = server;
        }

        public void run() {
            try {
                server.start();
            } catch (IOException e) {
                System.err.println(e);
            }
        }
    }

    /** A thread that acts as one client: sends a normal message and a blocked message. */
    private static class ClientThread extends Thread {
        private int port;
        private int number;
        boolean success = false;

        ClientThread(int port, int number) {
            this.port = port;
            this.number = number;
        }

        public void run() {
            try {
                String[] messages = {"client " + number, "BLOCKED " + number};
                List<String> replies = talkToServer(port, messages);
                if (replies.get(1).startsWith("ALLOW") && replies.get(2).startsWith("BLOCK")) {
                    success = true;
                }
            } catch (IOException e) {
                success = false;
            }
        }
    }

    /** Starts a server in the background and waits until it is ready. */
    private static void startServer(int port, RuleManager rules) throws InterruptedException {
        TCP_Server server = new TCP_Server(port, new FirewallEngine(rules), new FirewallLogger());
        ServerThread thread = new ServerThread(server);
        thread.setDaemon(true); // the thread stops when the tests finish
        thread.start();

        // Wait up to about 2.5 seconds for the server to start
        for (int i = 0; i < 50; i++) {
            if (canConnect(port)) {
                break;
            }
            Thread.sleep(50);
        }
    }

    /**
     * Connects to the server, reads the greeting, sends each message,
     * and returns every line the server sent back.
     */
    private static List<String> talkToServer(int port, String[] messages) throws IOException {
        List<String> replies = new ArrayList<String>();
        Socket socket = new Socket("127.0.0.1", port);

        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            String greeting = in.readLine();
            replies.add(greeting);

            // If the server blocked us, stop here
            if (greeting == null || greeting.startsWith("BLOCK")) {
                return replies;
            }

            for (int i = 0; i < messages.length; i++) {
                out.println(messages[i]);
                replies.add(in.readLine());
            }
        } finally {
            socket.close(); // always close the connection
        }
        return replies;
    }

    /** Returns true if a server is listening on this port. */
    private static boolean canConnect(int port) {
        try {
            Socket socket = new Socket("127.0.0.1", port);
            socket.close();
            return true;
        } catch (IOException e) {
            return false; // nothing is listening
        }
    }

    // =========================================================
    // General helpers
    // =========================================================

    /** Prints a section title. */
    private static void section(String name) {
        System.out.println();
        System.out.println("== " + name + " ==");
    }

    /** Prints PASS or FAIL and updates the counters. */
    private static void check(String name, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("  PASS  " + name);
        } else {
            failed++;
            System.out.println("  FAIL  " + name);
        }
    }

    /** Makes a text by repeating one character n times. */
    private static String makeText(char c, int n) {
        String text = "";
        for (int i = 0; i < n; i++) {
            text = text + c;
        }
        return text;
    }
}
