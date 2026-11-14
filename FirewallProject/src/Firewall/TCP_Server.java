package Firewall;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * TCP server protected by the firewall engine.
 *
 * Protocol (one line of text per request):
 *   client -> server : any text line, or "QUIT" to disconnect
 *   server -> client : "ALLOW: <reply>"  or  "BLOCK: <reason>"
 *
 * Usage: java Firewall.TCP_Server [port]      (default 9806)
 */
public class TCP_Server {

    public static final int DEFAULT_PORT = 9806;
    private static final int MAX_CLIENTS = 10;          // thread-pool size
    private static final int IDLE_TIMEOUT_MS = 60_000;  // drop idle clients after 60s
    private static final int MAX_LINE_LENGTH = 1024;    // reject oversized requests

    private final int port;
    private final FirewallEngine engine;
    private final FirewallLogger logger;
    private final ExecutorService pool = Executors.newFixedThreadPool(MAX_CLIENTS);
    private volatile ServerSocket serverSocket;
    private final java.util.Set<Socket> clients = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /** Stops accepting clients and disconnects everyone (used by the GUI). */
    public void stop() {
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) { }
        for (Socket c : clients) {
            try { c.close(); } catch (IOException ignored) { }
        }
        pool.shutdownNow();
    }

    public int getActiveClients() { return clients.size(); }

    public TCP_Server(int port, FirewallEngine engine, FirewallLogger logger) {
        this.port = port;
        this.engine = engine;
        this.logger = logger;
    }

    public void start() throws IOException {
        try (ServerSocket welcomeSocket = new ServerSocket(port)) {
            serverSocket = welcomeSocket;
            logger.logEvent("-", "Server listening on port " + port
                    + " (default policy: " + engine.getRuleManager().getDefaultPolicy() + ")");
            for (FirewallRule r : engine.getRuleManager().getRules()) {
                logger.logEvent("-", "Rule loaded: " + r);
            }

            while (!welcomeSocket.isClosed()) {
                Socket connectionSocket;
                try {
                    connectionSocket = welcomeSocket.accept();
                } catch (java.net.SocketException closed) {
                    break; // stop() closed the socket
                }
                clients.add(connectionSocket);
                pool.execute(() -> handleClient(connectionSocket));
            }
        } finally {
            pool.shutdown();
            logger.logEvent("-", "Server stopped");
        }
    }

    /** Runs on a pool thread, one call per connected client. */
    private void handleClient(Socket socket) {
        String clientIP = socket.getInetAddress().getHostAddress();
        int clientPort = socket.getPort(); // the client's (source) port, chosen by its OS

        try (Socket s = socket;
             BufferedReader in = new BufferedReader(
                     new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
             PrintWriter out = new PrintWriter(s.getOutputStream(), true)) {

            s.setSoTimeout(IDLE_TIMEOUT_MS);

            // Checkpoint 1: should this client be allowed to connect at all?
            FirewallDecision connDecision = engine.checkConnection(clientIP);
            logger.logDecision(clientIP, connDecision, null);
            if (!connDecision.isAllowed()) {
                out.println("BLOCK: Connection rejected - " + connDecision.getReason());
                return;
            }
            out.println("ALLOW: Connected to firewall server (your source port: " + clientPort + ")");

            String message;
            while ((message = in.readLine()) != null) {
                if (message.equalsIgnoreCase("QUIT")) {
                    out.println("ALLOW: Goodbye");
                    break;
                }
                if (message.length() > MAX_LINE_LENGTH) {
                    FirewallDecision tooLong = new FirewallDecision(FirewallDecision.Action.BLOCK,
                            "Malformed request: longer than " + MAX_LINE_LENGTH + " characters", null);
                    logger.logDecision(clientIP, tooLong, message);
                    out.println("BLOCK: " + tooLong.getReason());
                    continue;
                }

                // Checkpoint 2: inspect each message.
                FirewallDecision decision = engine.checkMessage(clientIP, message);
                logger.logDecision(clientIP, decision, message);

                if (decision.isAllowed()) {
                    out.println("ALLOW: " + processRequest(message));
                } else {
                    out.println("BLOCK: " + decision.getReason());
                }
            }
        } catch (SocketTimeoutException e) {
            logger.logEvent(clientIP, "Client idle for " + IDLE_TIMEOUT_MS / 1000 + "s; connection closed");
        } catch (IOException e) {
            // e.g. the client disconnected abruptly - the server keeps running
            logger.logEvent(clientIP, "Connection error: " + e.getMessage());
        } finally {
            clients.remove(socket);
            logger.logEvent(clientIP, "Client disconnected");
        }
    }

    /** The "real" service behind the firewall. Here it simply echoes. */
    private String processRequest(String message) {
        return "Server received \"" + message + "\"";
    }

    public static void main(String[] args) {
        int port = DEFAULT_PORT;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port '" + args[0] + "', using " + DEFAULT_PORT);
            }
        }

        try {
            Path rulesFile = Paths.get("rules.conf");
            RuleManager rules;
            if (Files.exists(rulesFile)) {
                rules = RuleManager.loadFromFile(rulesFile);
                System.out.println("Loaded rules from " + rulesFile.toAbsolutePath());
            } else {
                rules = RuleManager.defaults();
                System.out.println("rules.conf not found - using built-in default rules");
            }

            FirewallLogger logger = new FirewallLogger(Paths.get("logs", "firewall.log"));
            new TCP_Server(port, new FirewallEngine(rules), logger).start();

        } catch (java.net.BindException e) {
            System.err.println("Port " + port + " is already in use. Is another server running?");
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
        }
    }
}
