package Firewall;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ConnectException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;

/**
 * Interactive client. Type a message, press Enter, and see whether the
 * firewall allowed or blocked it. Type QUIT to exit.
 *
 * Usage: java Firewall.TCP_Client [host] [port]   (default localhost 9806)
 */
public class TCP_Client {

    public static void main(String[] args) {
        String host = args.length > 0 ? args[0] : "localhost";
        int port = TCP_Server.DEFAULT_PORT;
        if (args.length > 1) {
            try {
                port = Integer.parseInt(args[1]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port '" + args[1] + "', using " + port);
            }
        }

        try (Socket clientSocket = new Socket(host, port);
             BufferedReader fromServer = new BufferedReader(
                     new InputStreamReader(clientSocket.getInputStream(), StandardCharsets.UTF_8));
             PrintWriter toServer = new PrintWriter(clientSocket.getOutputStream(), true);
             BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in))) {

            System.out.println("Connected to " + host + ":" + port
                    + " from local port " + clientSocket.getLocalPort());

            // First line is the connection-level decision.
            String greeting = fromServer.readLine();
            if (greeting == null) {
                System.out.println("Server closed the connection.");
                return;
            }
            printResponse(greeting);
            if (greeting.startsWith("BLOCK")) {
                return;
            }

            System.out.println("Type a message (QUIT to exit):");
            String line;
            while (true) {
                System.out.print("> ");
                line = keyboard.readLine();
                if (line == null) line = "QUIT"; // end of input (Ctrl+D / Ctrl+Z)

                toServer.println(line);
                String response = fromServer.readLine();
                if (response == null) {
                    System.out.println("Server closed the connection.");
                    break;
                }
                printResponse(response);
                if (line.equalsIgnoreCase("QUIT")) break;
            }

        } catch (UnknownHostException e) {
            System.err.println("Unknown host: " + host);
        } catch (ConnectException e) {
            System.err.println("Could not connect to " + host + ":" + port
                    + " - is the server running? (" + e.getMessage() + ")");
        } catch (IOException e) {
            System.err.println("Connection error: " + e.getMessage());
        }
    }

    private static void printResponse(String response) {
        if (response.startsWith("ALLOW")) {
            System.out.println("[ALLOWED] " + response.substring(response.indexOf(':') + 1).trim());
        } else if (response.startsWith("BLOCK")) {
            System.out.println("[BLOCKED] " + response.substring(response.indexOf(':') + 1).trim());
        } else {
            System.out.println(response);
        }
    }
}
