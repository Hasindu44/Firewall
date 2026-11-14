# Java-Based Network Firewall Simulator

An educational, application-level firewall written in Java. A TCP server on port **9806** checks every client connection and every message against a set of rules, decides **ALLOW** or **BLOCK**, tells the client the result and logs it with the reason.

> This is a simulator. It filters only traffic sent to its own Java server, not all network traffic on the computer, and it works on text messages, not raw packets.

## Project structure

```
FirewallProject/
├── src/Firewall/
│   ├── TCP_Server.java        Accepts connections and asks the engine for decisions (thread pool)
│   ├── TCP_Client.java        Interactive console client
│   ├── FirewallEngine.java    Evaluates requests against rules
│   ├── FirewallRule.java      One rule: id, type, condition, action, enabled
│   ├── RuleManager.java       Ordered, thread-safe rule list, default policy, rules.conf loader
│   ├── FirewallLogger.java    Console and logs/firewall.log, with redaction of secrets
│   ├── FirewallDecision.java  ALLOW/BLOCK plus reason and rule id
│   └── FirewallTests.java     Self-contained test suite (no JUnit needed)
├── rules.conf                 Firewall rules (edit these to change the policy)
└── logs/firewall.log          Created automatically
```

## Running in Eclipse

1. **File → Import → General → Existing Projects into Workspace**, then select the `FirewallProject` folder.
2. Right-click `TCP_Server.java` and choose **Run As → Java Application**.
3. Right-click `TCP_Client.java` and choose **Run As → Java Application**. Type messages in the client's console. Type `QUIT` to exit.
   You can start several clients at once. Use the console dropdown to switch between them.
4. Right-click `FirewallTests.java` and choose **Run As → Java Application** to run all tests.

The server reads `rules.conf` and writes `logs/` relative to the working directory. In Eclipse the working directory is the project folder by default.

### Control panel (GUI)

Run `FirewallGUI.java` instead of `TCP_Server.java` to get the **Firewall Shield** control panel. It's built in pure Swing and needs no extra libraries.

- **Dashboard:** animated protection status, Start/Stop button, port picker, session info (uptime, active rules, default policy), live counters, a 60-second traffic chart and a list of recent threats.
- **Activity:** every decision in a live table with colour-coded tags, a search box, All/Allowed/Blocked/Events filters, and CSV export to `logs/`.
- **Rules:** create, edit (double-click), reorder and delete rules, turn rules on/off with switches, change the default policy and save to `rules.conf`. Changes apply to the running server straight away.

From the command line:

```
javac -d bin src/Firewall/*.java
java -cp bin Firewall.FirewallGUI         # control panel (starts/stops the server)
java -cp bin Firewall.TCP_Server          # console-only server; optional: port number
java -cp bin Firewall.TCP_Client          # optional: host port
java -cp bin Firewall.FirewallTests
```

## How a request is processed

1. The client connects. The server reads the client IP with `getInetAddress().getHostAddress()`.
2. **Connection check:** only IP rules can match at this point. If the result is BLOCK, the client receives `BLOCK: Connection rejected ...` and the connection is closed.
3. **Message check:** every line the client sends is checked against all rules.
4. The client receives `ALLOW: <reply>` or `BLOCK: <reason>`.
5. Each decision is logged with a timestamp, the IP, the decision, the reason and a short message summary.

## Rule evaluation (priority)

- Rules are checked **top to bottom**, in the order they appear in `rules.conf`.
- The **first matching enabled rule wins**.
- If no rule matches, the **default policy** applies (`default = ALLOW` or `default = BLOCK`).

With the shipped rules, a message containing `BLOCKED` from `127.0.0.1` is **blocked**. Rule 1 (keyword) comes before rule 3 (IP allow), so it matches first. To make an allowlisted IP bypass keyword checks, move its rule above the keyword rule.

## rules.conf format

```
default = ALLOW
# id | type    | condition    | action | enabled
1    | KEYWORD | BLOCKED      | BLOCK  | true
2    | IP      | 192.168.1.20 | BLOCK  | true
3    | IP      | 127.0.0.1    | ALLOW  | true
```

- `KEYWORD`: the message contains the text. Matching is case-insensitive.
- `IP`: the client IP is exactly the given address.

A strict allowlist policy looks like this: `default = BLOCK` plus `IP ... ALLOW` rules for the permitted addresses.

If the file has a bad line, the server refuses to start and reports the line number.

## Other behaviour

- **Concurrency:** a fixed pool of 10 threads handles clients. Rules are stored in a `CopyOnWriteArrayList`, so they can be read safely by many threads at once.
- **Idle timeout:** clients that send nothing for 60 seconds are disconnected.
- **Malformed requests:** lines longer than 1024 characters are blocked.
- **Abrupt disconnects:** these are logged, and the server keeps running.
- **Log privacy:** messages that look like `password=`, `token:`, `api_key=` and similar are logged as `[redacted]`. Long messages are truncated.

## Ports: source and destination

The server listens on the fixed **destination** port 9806. The client's operating system picks a temporary **source** port for each connection. The client prints this port, and the server echoes it back in its greeting. If nothing is listening on 9806, the client reports "Could not connect ... is the server running?".

## Testing an IP that is not loopback

When you test on one machine, every client appears as `127.0.0.1`. To test IP rules, you can:
- change rules.conf so that it blocks `127.0.0.1`, or
- run the client on another machine on your local network with `java -cp bin Firewall.TCP_Client <server-ip>`, then block that machine's IP. You may need to allow port 9806 through the operating system firewall.

The IP the server sees may be a loopback, private, NAT or proxy address. It does not reliably identify a person.

## Limitations and future work

There is no encryption and no authentication. Rules can only be changed by restarting the server.

Ideas for later: a GUI dashboard, live rule reloading, CIDR ranges such as `192.168.1.0/24`, connection-rate limiting, TLS, and integration with operating-system firewalls.
