package Firewall;

import java.awt.*;
import java.awt.event.*;
import java.awt.geom.*;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.IntConsumer;
import java.util.function.IntFunction;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.plaf.basic.BasicScrollBarUI;
import javax.swing.table.*;

import Firewall.FirewallDecision.Action;

/**
 * Firewall Shield - control panel for the firewall simulator.
 *
 * Run this class instead of TCP_Server. It starts and stops the server,
 * shows live traffic and statistics, and edits the rules.
 * Pure Swing (no external libraries): every widget is custom painted.
 */
public class FirewallGUI extends JFrame {

    // =================================================================
    //  Theme
    // =================================================================
    static final Color BG        = new Color(0x0D1117);
    static final Color SIDEBAR   = new Color(0x090C11);
    static final Color SURFACE   = new Color(0x141A22);
    static final Color SURFACE2  = new Color(0x1B232E);
    static final Color SURFACE3  = new Color(0x253040);
    static final Color BORDER    = new Color(0x222B37);
    static final Color BORDER_HI = new Color(0x323E4E);
    static final Color ROWLINE   = new Color(0x1C242F);
    static final Color HOVER     = new Color(0x18202A);
    static final Color SELECT    = new Color(0x1C3150);
    static final Color TEXT      = new Color(0xE6EDF3);
    static final Color MUTED     = new Color(0x8B96A5);
    static final Color SUBTLE    = new Color(0x5A6573);
    static final Color ACCENT    = new Color(0x4C8DFF);
    static final Color GREEN     = new Color(0x2FBF71);
    static final Color RED       = new Color(0xF0524D);
    static final Color AMBER     = new Color(0xE3A43A);
    static final Color PURPLE    = new Color(0x9B7BFF);

    private static final Set<String> FAMILIES = new HashSet<>(Arrays.asList(
            GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames()));
    private static final String UI_FONT   = family("Segoe UI", "Inter", "Helvetica Neue", "Arial");
    private static final String SEMI_FONT = family("Segoe UI Semibold", UI_FONT);
    private static final String MONO_FONT = family("Cascadia Mono", "Consolas", "Menlo", Font.MONOSPACED);

    private static String family(String... names) {
        for (String n : names) if (FAMILIES.contains(n)) return n;
        return Font.SANS_SERIF;
    }
    static Font font(int size) { return new Font(UI_FONT, Font.PLAIN, size); }
    static Font semi(int size) {
        return SEMI_FONT.equals(UI_FONT) ? new Font(UI_FONT, Font.BOLD, size) : new Font(SEMI_FONT, Font.PLAIN, size);
    }
    static Font mono(int size) { return new Font(MONO_FONT, Font.PLAIN, size); }

    private static final Path RULES_FILE = Paths.get("rules.conf");
    private static final String VERSION = "1.0";
    private static final String[] PAGES = {"Dashboard", "Activity", "Rules"};
    private static final String[] PAGE_ICONS = {"dashboard", "activity", "rules"};
    private static final String[] PAGE_SUBTITLES = {
            "Real-time overview of your firewall",
            "Every connection and message decision, newest first",
            "Rules are checked from top to bottom. The first enabled rule that matches decides."
    };

    // =================================================================
    //  State
    // =================================================================
    private RuleManager rules;
    private FirewallLogger logger;
    private volatile TCP_Server server;
    private volatile boolean running;
    private long startedAt;
    private int runningPort;
    private boolean dirty;
    private String startupWarning;
    private final AtomicInteger allowed = new AtomicInteger();
    private final AtomicInteger blocked = new AtomicInteger();
    private final AtomicInteger connections = new AtomicInteger();
    private final AtomicInteger secAllowed = new AtomicInteger();
    private final AtomicInteger secBlocked = new AtomicInteger();

    // =================================================================
    //  Widgets
    // =================================================================
    private final CardLayout cards = new CardLayout();
    private final JPanel content = new JPanel(cards);
    private final List<NavItem> navItems = new ArrayList<>();
    private JLabel pageTitle, pageSubtitle, clockLbl;
    private StatusPill headerPill, sidePill;
    private JLabel sideDetail;

    private ShieldRing ring;
    private JLabel heroTitle, heroSub, uptimeVal, rulesVal, policyVal;
    private FlatButton toggleBtn;
    private StyledField portField;
    private StatCard allowedCard, blockedCard, connCard, activeCard;
    private TrafficChart chart;
    private final DefaultListModel<String[]> threatModel = new DefaultListModel<>();

    private final DefaultTableModel activityModel =
            new DefaultTableModel(new String[]{"Time", "Client IP", "Decision", "Reason", "Message"}, 0) {
                @Override public boolean isCellEditable(int r, int c) { return false; }
            };
    private TableRowSorter<DefaultTableModel> activitySorter;
    private StyledField searchField;
    private Segmented filterSeg;
    private int activityFilter;
    private JLabel activityCount;

    private DefaultTableModel rulesModel;
    private JTable rulesTable;
    private Segmented policySeg;
    private FlatButton saveBtn, editBtn, deleteBtn, upBtn, downBtn;

    private JLabel statusLeft, statusRight;
    private JComponent toast;
    private Timer toastTimer;

    // =================================================================
    //  Construction
    // =================================================================
    public FirewallGUI() {
        super("Firewall Shield");
        loadRules();
        try {
            logger = new FirewallLogger(Paths.get("logs", "firewall.log"));
        } catch (IOException e) {
            logger = new FirewallLogger();
        }

        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1260, 800);
        setMinimumSize(new Dimension(1060, 680));
        setLocationRelativeTo(null);
        setIconImages(List.of(appIcon(16), appIcon(32), appIcon(64)));

        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(BG);
        root.add(buildSidebar(), BorderLayout.WEST);

        JPanel main = new JPanel(new BorderLayout());
        main.setBackground(BG);
        main.add(buildHeader(), BorderLayout.NORTH);
        content.setBackground(BG);
        content.add(buildDashboard(), PAGES[0]);
        content.add(buildActivity(), PAGES[1]);
        content.add(buildRules(), PAGES[2]);
        main.add(content, BorderLayout.CENTER);
        main.add(buildStatusBar(), BorderLayout.SOUTH);
        root.add(main, BorderLayout.CENTER);
        setContentPane(root);

        logger.addListener(this::onLogEntry);
        new Timer(1000, e -> tick()).start();

        addWindowListener(new WindowAdapter() {
            @Override public void windowClosing(WindowEvent e) {
                if (running && server != null) server.stop();
            }
        });

        selectPage(PAGES[0]);
        updateStatus();
        tick();

        if (startupWarning != null) {
            SwingUtilities.invokeLater(() -> dialog("rules.conf could not be loaded",
                    startupWarning + "\n\nThe built-in rules are being used instead.", true, "OK", null));
        }
    }

    // =================================================================
    //  Sidebar, header, status bar
    // =================================================================
    private JComponent buildSidebar() {
        JPanel side = new JPanel(new BorderLayout()) {
            @Override protected void paintComponent(Graphics g) {
                g.setColor(SIDEBAR);
                g.fillRect(0, 0, getWidth(), getHeight());
                g.setColor(BORDER);
                g.fillRect(getWidth() - 1, 0, 1, getHeight());
            }
        };
        side.setPreferredSize(new Dimension(236, 0));
        side.setBorder(new EmptyBorder(22, 14, 18, 15));

        JPanel top = vbox();
        JPanel brand = new JPanel(new BorderLayout(12, 0));
        brand.setOpaque(false);
        brand.add(new JLabel(new ImageIcon(appIcon(38))), BorderLayout.WEST);
        JPanel names = vbox();
        names.add(Box.createVerticalGlue());
        names.add(label("Firewall Shield", semi(15), TEXT));
        names.add(Box.createVerticalStrut(1));
        names.add(label("Network Protection", font(11), MUTED));
        names.add(Box.createVerticalGlue());
        brand.add(names, BorderLayout.CENTER);
        brand.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        brand.setAlignmentX(LEFT_ALIGNMENT);
        top.add(Box.createVerticalStrut(2));
        top.add(brand);
        top.add(Box.createVerticalStrut(30));

        JLabel menu = label("MENU", semi(10), SUBTLE);
        menu.setBorder(new EmptyBorder(0, 14, 8, 0));
        top.add(menu);
        for (int i = 0; i < PAGES.length; i++) {
            String name = PAGES[i];
            NavItem item = new NavItem(name, PAGE_ICONS[i], () -> selectPage(name));
            navItems.add(item);
            top.add(item);
            top.add(Box.createVerticalStrut(4));
        }
        side.add(top, BorderLayout.NORTH);

        RoundPanel card = new RoundPanel(12, SURFACE, BORDER);
        card.setLayout(new BorderLayout(0, 8));
        card.setBorder(new EmptyBorder(12, 12, 12, 12));
        sidePill = new StatusPill();
        sideDetail = label(" ", font(12), MUTED);
        card.add(sidePill, BorderLayout.NORTH);
        card.add(sideDetail, BorderLayout.CENTER);
        card.setAlignmentX(LEFT_ALIGNMENT);

        JPanel bottom = vbox();
        bottom.add(card);
        bottom.add(Box.createVerticalStrut(12));
        JLabel ver = label("Version " + VERSION + "  ·  Simulator edition", font(11), SUBTLE);
        ver.setBorder(new EmptyBorder(0, 4, 0, 0));
        bottom.add(ver);
        side.add(bottom, BorderLayout.SOUTH);
        return side;
    }

    private JComponent buildHeader() {
        JPanel h = new JPanel(new BorderLayout());
        h.setOpaque(false);
        h.setBorder(new EmptyBorder(24, 28, 18, 28));

        JPanel titles = vbox();
        pageTitle = label(" ", semi(24), TEXT);
        pageSubtitle = label(" ", font(13), MUTED);
        titles.add(pageTitle);
        titles.add(Box.createVerticalStrut(3));
        titles.add(pageSubtitle);
        h.add(titles, BorderLayout.WEST);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 14, 0));
        right.setOpaque(false);
        clockLbl = label(" ", font(13), MUTED);
        clockLbl.setIcon(new VIcon("clock", 15, SUBTLE));
        clockLbl.setIconTextGap(7);
        headerPill = new StatusPill();
        right.add(clockLbl);
        right.add(headerPill);
        JPanel rightWrap = new JPanel(new GridBagLayout());
        rightWrap.setOpaque(false);
        rightWrap.add(right);
        h.add(rightWrap, BorderLayout.EAST);
        return h;
    }

    private JComponent buildStatusBar() {
        JPanel bar = new JPanel(new BorderLayout()) {
            @Override protected void paintComponent(Graphics g) {
                g.setColor(SIDEBAR);
                g.fillRect(0, 0, getWidth(), getHeight());
                g.setColor(BORDER);
                g.fillRect(0, 0, getWidth(), 1);
            }
        };
        bar.setBorder(new EmptyBorder(7, 28, 7, 28));
        statusLeft = label(" ", font(12), MUTED);
        statusLeft.setIconTextGap(8);
        statusRight = label(" ", font(12), SUBTLE);
        bar.add(statusLeft, BorderLayout.WEST);
        bar.add(statusRight, BorderLayout.EAST);
        return bar;
    }

    private void selectPage(String name) {
        cards.show(content, name);
        for (int i = 0; i < PAGES.length; i++) {
            navItems.get(i).setSelected(PAGES[i].equals(name));
            if (PAGES[i].equals(name)) {
                pageTitle.setText(name);
                pageSubtitle.setText(PAGE_SUBTITLES[i]);
            }
        }
    }

    // =================================================================
    //  Dashboard
    // =================================================================
    private JComponent buildDashboard() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setOpaque(false);
        p.setBorder(new EmptyBorder(0, 28, 22, 28));

        GridBagConstraints g = new GridBagConstraints();
        g.gridx = 0; g.gridy = 0; g.gridwidth = 2;
        g.fill = GridBagConstraints.BOTH; g.weightx = 1;
        g.insets = new Insets(0, 0, 16, 0);
        p.add(buildHero(), g);

        JPanel stats = new JPanel(new GridLayout(1, 4, 16, 0));
        stats.setOpaque(false);
        allowedCard = new StatCard("Allowed requests", "check", GREEN);
        blockedCard = new StatCard("Threats blocked", "block", RED);
        connCard    = new StatCard("Connections", "network", ACCENT);
        activeCard  = new StatCard("Active clients", "users", AMBER);
        stats.add(allowedCard);
        stats.add(blockedCard);
        stats.add(connCard);
        stats.add(activeCard);
        g.gridy = 1;
        p.add(stats, g);

        g.gridy = 2; g.gridwidth = 1; g.weighty = 1;
        g.weightx = 0.62; g.insets = new Insets(0, 0, 0, 16);
        p.add(buildTrafficCard(), g);
        g.gridx = 1; g.weightx = 0.38; g.insets = new Insets(0, 0, 0, 0);
        p.add(buildThreatsCard(), g);
        return p;
    }

    private JComponent buildHero() {
        RoundPanel hero = new RoundPanel(16, SURFACE, BORDER);
        hero.setLayout(new BorderLayout(26, 0));
        hero.setBorder(new EmptyBorder(18, 22, 18, 26));

        ring = new ShieldRing();
        hero.add(ring, BorderLayout.WEST);

        JPanel text = vbox();
        heroTitle = label(" ", semi(26), TEXT);
        heroSub = label(" ", font(14), MUTED);
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        controls.setOpaque(false);
        toggleBtn = new FlatButton("Start protection", "power", Kind.SUCCESS);
        toggleBtn.addActionListener(e -> toggleProtection());
        portField = new StyledField(null, "9806");
        portField.setText(String.valueOf(TCP_Server.DEFAULT_PORT));
        portField.setPreferredSize(new Dimension(86, 38));
        controls.add(toggleBtn);
        controls.add(Box.createHorizontalStrut(20));
        JLabel portLbl = label("Listening port", font(13), MUTED);
        portLbl.setBorder(new EmptyBorder(0, 0, 0, 10));
        controls.add(portLbl);
        controls.add(portField);

        text.add(Box.createVerticalGlue());
        text.add(label("PROTECTION STATUS", semi(11), SUBTLE));
        text.add(Box.createVerticalStrut(6));
        text.add(heroTitle);
        text.add(Box.createVerticalStrut(4));
        text.add(heroSub);
        text.add(Box.createVerticalStrut(18));
        text.add(controls);
        text.add(Box.createVerticalGlue());
        for (Component c : text.getComponents()) ((JComponent) c).setAlignmentX(LEFT_ALIGNMENT);
        hero.add(text, BorderLayout.CENTER);

        JPanel session = new JPanel(new GridLayout(0, 1, 0, 6));
        session.setOpaque(false);
        session.setBorder(new CompoundBorder(new MatteBorder(0, 1, 0, 0, BORDER), new EmptyBorder(8, 24, 8, 0)));
        session.setPreferredSize(new Dimension(270, 0));
        uptimeVal = label("-", semi(13), TEXT);
        rulesVal = label("-", semi(13), TEXT);
        policyVal = label("-", semi(13), TEXT);
        session.add(label("SESSION", semi(11), SUBTLE));
        session.add(infoRow("clock", "Uptime", uptimeVal));
        session.add(infoRow("rules", "Active rules", rulesVal));
        session.add(infoRow("shield", "Default policy", policyVal));
        session.add(infoRow("network", "Max clients", label("10 at a time", semi(13), TEXT)));
        hero.add(session, BorderLayout.EAST);
        return hero;
    }

    private static JPanel infoRow(String icon, String key, JLabel value) {
        JPanel row = new JPanel(new BorderLayout());
        row.setOpaque(false);
        JLabel k = label(key, font(13), MUTED);
        k.setIcon(new VIcon(icon, 15, SUBTLE));
        k.setIconTextGap(9);
        row.add(k, BorderLayout.WEST);
        row.add(value, BorderLayout.EAST);
        return row;
    }

    private JComponent buildTrafficCard() {
        RoundPanel c = new RoundPanel(16, SURFACE, BORDER);
        c.setLayout(new BorderLayout(0, 14));
        c.setBorder(new EmptyBorder(18, 20, 14, 20));
        JPanel head = new JPanel(new BorderLayout());
        head.setOpaque(false);
        head.add(cardTitle("Live traffic", "Decisions per second over the last 60 seconds"), BorderLayout.WEST);
        JPanel legend = new JPanel(new FlowLayout(FlowLayout.RIGHT, 14, 0));
        legend.setOpaque(false);
        legend.add(legend("Allowed", GREEN));
        legend.add(legend("Blocked", RED));
        head.add(legend, BorderLayout.EAST);
        c.add(head, BorderLayout.NORTH);
        chart = new TrafficChart();
        c.add(chart, BorderLayout.CENTER);
        c.setPreferredSize(new Dimension(300, 250));
        c.setMinimumSize(new Dimension(200, 200));
        return c;
    }

    private JComponent buildThreatsCard() {
        RoundPanel c = new RoundPanel(16, SURFACE, BORDER);
        c.setLayout(new BorderLayout(0, 10));
        c.setBorder(new EmptyBorder(18, 20, 10, 14));
        JPanel head = new JPanel(new BorderLayout());
        head.setOpaque(false);
        head.add(cardTitle("Recent threats", "Latest blocked connections and messages"), BorderLayout.WEST);
        JLabel viewAll = label("View all", semi(12), ACCENT);
        viewAll.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        viewAll.setBorder(new EmptyBorder(0, 0, 0, 6));
        viewAll.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) {
                selectPage("Activity");
                filterSeg.setSelected(2);
            }
        });
        JPanel vw = new JPanel(new BorderLayout());
        vw.setOpaque(false);
        vw.add(viewAll, BorderLayout.NORTH);
        head.add(vw, BorderLayout.EAST);
        c.add(head, BorderLayout.NORTH);

        JList<String[]> list = new JList<>(threatModel) {
            @Override protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                if (getModel().getSize() == 0) {
                    paintEmptyState(this, g, "shield", "No threats detected",
                            "Blocked activity will appear here");
                }
            }
        };
        list.setBackground(SURFACE);
        list.setCellRenderer(new ThreatRenderer());
        list.setFixedCellHeight(58);
        list.setFocusable(false);
        list.setSelectionModel(new DefaultListSelectionModel() {
            @Override public void setSelectionInterval(int a, int b) { }
            @Override public void addSelectionInterval(int a, int b) { }
        });
        list.setBorder(new EmptyBorder(0, 0, 0, 6));
        c.add(scroll(list), BorderLayout.CENTER);
        c.setPreferredSize(new Dimension(300, 250));
        c.setMinimumSize(new Dimension(200, 200));
        return c;
    }

    // =================================================================
    //  Activity
    // =================================================================
    private JComponent buildActivity() {
        JPanel p = new JPanel(new BorderLayout(0, 14));
        p.setOpaque(false);
        p.setBorder(new EmptyBorder(0, 28, 22, 28));

        JPanel tb = new JPanel(new BorderLayout(12, 0));
        tb.setOpaque(false);
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        left.setOpaque(false);
        ((FlowLayout) left.getLayout()).setHgap(0);
        searchField = new StyledField("search", "Search IP, reason or message...");
        searchField.setPreferredSize(new Dimension(320, 38));
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e)  { activitySorter.sort(); }
            public void removeUpdate(DocumentEvent e)  { activitySorter.sort(); }
            public void changedUpdate(DocumentEvent e) { activitySorter.sort(); }
        });
        filterSeg = new Segmented(new String[]{"All", "Allowed", "Blocked", "Events"}, 0, i -> {
            activityFilter = i;
            activitySorter.sort();
        });
        filterSeg.setAccent(i -> i == 1 ? GREEN : i == 2 ? RED : null);
        left.add(searchField);
        left.add(Box.createHorizontalStrut(10));
        left.add(filterSeg);
        tb.add(left, BorderLayout.WEST);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        right.setOpaque(false);
        activityCount = label(" ", font(12), MUTED);
        activityCount.setBorder(new EmptyBorder(0, 0, 0, 14));
        FlatButton export = new FlatButton("Export CSV", "export", Kind.GHOST);
        export.addActionListener(e -> exportActivity());
        FlatButton clear = new FlatButton("Clear", "trash", Kind.GHOST);
        clear.addActionListener(e -> {
            activityModel.setRowCount(0);
            toast("Activity log cleared", MUTED, "trash");
        });
        right.add(activityCount);
        right.add(export);
        right.add(Box.createHorizontalStrut(8));
        right.add(clear);
        JPanel rw = new JPanel(new GridBagLayout());
        rw.setOpaque(false);
        rw.add(right);
        tb.add(rw, BorderLayout.EAST);
        p.add(tb, BorderLayout.NORTH);

        JTable table = new EmptyAwareTable(activityModel, "activity",
                "No activity yet", "Start protection and connect a client to see decisions here");
        styleTable(table);
        TableColumnModel cm = table.getColumnModel();
        cm.getColumn(0).setPreferredWidth(150);
        cm.getColumn(1).setPreferredWidth(130);
        cm.getColumn(2).setPreferredWidth(100);
        cm.getColumn(3).setPreferredWidth(330);
        cm.getColumn(4).setPreferredWidth(240);
        cm.getColumn(0).setCellRenderer(new CellRenderer(font(13), MUTED));
        cm.getColumn(1).setCellRenderer(new CellRenderer(mono(13), TEXT));
        cm.getColumn(2).setCellRenderer(new PillRenderer(
                v -> "BLOCK".equals(v) ? RED : "ALLOW".equals(v) ? GREEN : MUTED,
                v -> "INFO".equals(v) ? "EVENT" : String.valueOf(v)));
        cm.getColumn(4).setCellRenderer(new CellRenderer(mono(12), MUTED));

        activitySorter = new TableRowSorter<>(activityModel);
        for (int i = 0; i < activityModel.getColumnCount(); i++) activitySorter.setSortable(i, false);
        activitySorter.setRowFilter(new RowFilter<DefaultTableModel, Integer>() {
            @Override public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> e) {
                String d = e.getStringValue(2);
                if (activityFilter == 1 && !"ALLOW".equals(d)) return false;
                if (activityFilter == 2 && !"BLOCK".equals(d)) return false;
                if (activityFilter == 3 && !"INFO".equals(d)) return false;
                String q = searchField.getText().trim().toLowerCase();
                if (q.isEmpty()) return true;
                for (int i = 0; i < 5; i++) {
                    if (e.getStringValue(i).toLowerCase().contains(q)) return true;
                }
                return false;
            }
        });
        activitySorter.addRowSorterListener(e -> updateActivityCount());
        table.setRowSorter(activitySorter);
        updateActivityCount();

        p.add(tableCard(table), BorderLayout.CENTER);
        return p;
    }

    private void updateActivityCount() {
        activityCount.setText(String.format("Showing %,d of %,d events",
                activitySorter.getViewRowCount(), activityModel.getRowCount()));
    }

    private void exportActivity() {
        String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        Path file = Paths.get("logs", "activity-" + stamp + ".csv");
        try {
            Files.createDirectories(file.getParent());
            int n = activitySorter.getViewRowCount();
            try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(file, StandardCharsets.UTF_8))) {
                out.println("Time,Client IP,Decision,Reason,Message");
                for (int v = 0; v < n; v++) {
                    int m = activitySorter.convertRowIndexToModel(v);
                    StringBuilder sb = new StringBuilder();
                    for (int c = 0; c < 5; c++) {
                        if (c > 0) sb.append(',');
                        sb.append('"').append(String.valueOf(activityModel.getValueAt(m, c)).replace("\"", "\"\"")).append('"');
                    }
                    out.println(sb);
                }
            }
            toast(String.format("Exported %,d rows to %s", n, file), GREEN, "export");
        } catch (IOException ex) {
            dialog("Export failed", ex.getMessage(), true, "OK", null);
        }
    }

    // =================================================================
    //  Rules
    // =================================================================
    private JComponent buildRules() {
        JPanel p = new JPanel(new BorderLayout(0, 14));
        p.setOpaque(false);
        p.setBorder(new EmptyBorder(0, 28, 22, 28));

        JPanel tb = new JPanel(new BorderLayout());
        tb.setOpaque(false);
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        left.setOpaque(false);
        FlatButton addBtn = new FlatButton("New rule", "plus", Kind.PRIMARY);
        addBtn.addActionListener(e -> addRule());
        editBtn = new FlatButton("Edit", "edit", Kind.GHOST);
        editBtn.addActionListener(e -> editSelectedRule());
        upBtn = new FlatButton("", "up", Kind.GHOST);
        upBtn.setToolTipText("Move up (higher priority)");
        upBtn.addActionListener(e -> moveRule(-1));
        downBtn = new FlatButton("", "down", Kind.GHOST);
        downBtn.setToolTipText("Move down (lower priority)");
        downBtn.addActionListener(e -> moveRule(1));
        deleteBtn = new FlatButton("Delete", "trash", Kind.DANGER_SOFT);
        deleteBtn.addActionListener(e -> deleteSelectedRule());
        left.add(addBtn);
        left.add(Box.createHorizontalStrut(14));
        left.add(editBtn);
        left.add(Box.createHorizontalStrut(8));
        left.add(upBtn);
        left.add(Box.createHorizontalStrut(8));
        left.add(downBtn);
        left.add(Box.createHorizontalStrut(8));
        left.add(deleteBtn);
        tb.add(left, BorderLayout.WEST);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        right.setOpaque(false);
        JLabel pl = label("Default policy", font(13), MUTED);
        pl.setBorder(new EmptyBorder(0, 0, 0, 10));
        policySeg = new Segmented(new String[]{"Allow", "Block"},
                rules.getDefaultPolicy() == Action.ALLOW ? 0 : 1, i -> {
                    rules.setDefaultPolicy(i == 0 ? Action.ALLOW : Action.BLOCK);
                    markDirty();
                });
        policySeg.setAccent(i -> i == 0 ? GREEN : RED);
        saveBtn = new FlatButton("Save", "save", Kind.GHOST);
        saveBtn.addActionListener(e -> saveRules());
        right.add(pl);
        right.add(policySeg);
        right.add(Box.createHorizontalStrut(14));
        right.add(saveBtn);
        tb.add(right, BorderLayout.EAST);
        p.add(tb, BorderLayout.NORTH);

        rulesModel = new DefaultTableModel(new String[]{"Priority", "ID", "Type", "Condition", "Action", "Status"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        rulesTable = new EmptyAwareTable(rulesModel, "rules",
                "No rules", "All traffic follows the default policy. Click New rule to add one.");
        styleTable(rulesTable);
        rulesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        TableColumnModel cm = rulesTable.getColumnModel();
        cm.getColumn(0).setPreferredWidth(80);
        cm.getColumn(1).setPreferredWidth(60);
        cm.getColumn(2).setPreferredWidth(130);
        cm.getColumn(3).setPreferredWidth(320);
        cm.getColumn(4).setPreferredWidth(110);
        cm.getColumn(5).setPreferredWidth(140);
        cm.getColumn(0).setCellRenderer(new CellRenderer(semi(13), MUTED));
        cm.getColumn(1).setCellRenderer(new CellRenderer(mono(13), SUBTLE));
        cm.getColumn(2).setCellRenderer(new PillRenderer(
                v -> "IP".equals(v) ? PURPLE : ACCENT,
                v -> "IP".equals(v) ? "IP ADDRESS" : String.valueOf(v)));
        cm.getColumn(3).setCellRenderer(new CellRenderer(mono(13), TEXT));
        cm.getColumn(4).setCellRenderer(new PillRenderer(
                v -> "BLOCK".equals(v) ? RED : GREEN, String::valueOf));
        cm.getColumn(5).setCellRenderer(new SwitchRenderer());

        rulesTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) {
                int row = rulesTable.rowAtPoint(e.getPoint());
                int col = rulesTable.columnAtPoint(e.getPoint());
                if (row < 0) return;
                if (col == 5 && e.getClickCount() == 1) {
                    FirewallRule r = rules.getRule((Integer) rulesModel.getValueAt(row, 1));
                    if (r != null) {
                        r.setEnabled(!r.isEnabled());
                        rulesModel.setValueAt(r.isEnabled(), row, 5);
                        markDirty();
                        toast("Rule #" + r.getId() + (r.isEnabled() ? " enabled" : " disabled"),
                                r.isEnabled() ? GREEN : MUTED, r.isEnabled() ? "check" : "power");
                    }
                } else if (e.getClickCount() == 2) {
                    editSelectedRule();
                }
            }
        });
        rulesTable.getSelectionModel().addListSelectionListener(e -> updateRuleButtons());
        refreshRulesTable();
        updateRuleButtons();
        p.add(tableCard(rulesTable), BorderLayout.CENTER);

        RoundPanel hint = new RoundPanel(12, alpha(ACCENT, 18), alpha(ACCENT, 60));
        hint.setLayout(new BorderLayout());
        hint.setBorder(new EmptyBorder(11, 14, 11, 14));
        JLabel ht = label("<html>Rules are checked from top to bottom, and the first enabled rule that matches decides. "
                + "Changes apply to the running engine straight away. Click <b>Save</b> to keep them in rules.conf.</html>",
                font(12), new Color(0xA9C4F5));
        ht.setIcon(new VIcon("info", 16, ACCENT));
        ht.setIconTextGap(10);
        hint.add(ht);
        p.add(hint, BorderLayout.SOUTH);
        return p;
    }

    private void updateRuleButtons() {
        int row = rulesTable.getSelectedRow();
        boolean sel = row >= 0;
        editBtn.setEnabled(sel);
        deleteBtn.setEnabled(sel);
        upBtn.setEnabled(sel && row > 0);
        downBtn.setEnabled(sel && row < rulesModel.getRowCount() - 1);
    }

    private void refreshRulesTable() {
        int sel = rulesTable.getSelectedRow();
        rulesModel.setRowCount(0);
        int i = 1;
        for (FirewallRule r : rules.getRules()) {
            rulesModel.addRow(new Object[]{"#" + i++, r.getId(), r.getType().name(), r.getCondition(),
                    r.getAction().name(), r.isEnabled()});
        }
        if (sel >= 0 && sel < rulesModel.getRowCount()) rulesTable.setRowSelectionInterval(sel, sel);
        updateRuleButtons();
    }

    private FirewallRule selectedRule() {
        int row = rulesTable.getSelectedRow();
        return row < 0 ? null : rules.getRule((Integer) rulesModel.getValueAt(row, 1));
    }

    /** RuleManager has no reorder or replace method, so the list is rebuilt in the new order. */
    private void replaceAllRules(List<FirewallRule> list) {
        for (FirewallRule r : rules.getRules()) rules.removeRule(r.getId());
        for (FirewallRule r : list) rules.addRule(r);
    }

    private void addRule() {
        int nextId = rules.getRules().stream().mapToInt(FirewallRule::getId).max().orElse(0) + 1;
        FirewallRule r = ruleDialog(null, nextId);
        if (r == null) return;
        rules.addRule(r);
        refreshRulesTable();
        int last = rulesModel.getRowCount() - 1;
        rulesTable.setRowSelectionInterval(last, last);
        markDirty();
        toast("Rule #" + r.getId() + " created", GREEN, "plus");
    }

    private void editSelectedRule() {
        FirewallRule old = selectedRule();
        if (old == null) return;
        FirewallRule updated = ruleDialog(old, old.getId());
        if (updated == null) return;
        List<FirewallRule> list = new ArrayList<>(rules.getRules());
        list.set(list.indexOf(old), updated);
        replaceAllRules(list);
        refreshRulesTable();
        markDirty();
        toast("Rule #" + updated.getId() + " updated", ACCENT, "edit");
    }

    private void deleteSelectedRule() {
        FirewallRule r = selectedRule();
        if (r == null) return;
        if (!dialog("Delete rule #" + r.getId() + "?",
                r.getAction() + " " + (r.getType() == FirewallRule.Type.IP ? "IP address " : "keyword ")
                        + "\"" + r.getCondition() + "\"\n\nThis can't be undone unless you reload rules.conf.",
                true, "Delete", "Cancel")) return;
        rules.removeRule(r.getId());
        refreshRulesTable();
        markDirty();
        toast("Rule #" + r.getId() + " deleted", RED, "trash");
    }

    private void moveRule(int delta) {
        int row = rulesTable.getSelectedRow();
        List<FirewallRule> list = new ArrayList<>(rules.getRules());
        int target = row + delta;
        if (row < 0 || target < 0 || target >= list.size()) return;
        java.util.Collections.swap(list, row, target);
        replaceAllRules(list);
        refreshRulesTable();
        rulesTable.setRowSelectionInterval(target, target);
        markDirty();
    }

    private void markDirty() {
        dirty = true;
        updateStatus();
    }

    private void saveRules() {
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(RULES_FILE, StandardCharsets.UTF_8))) {
            out.println("# Firewall rules (saved by Firewall Shield)");
            out.println("# Rules are evaluated TOP TO BOTTOM. The FIRST matching rule wins.");
            out.println("# Format:  id | type | condition | action | enabled");
            out.println();
            out.println("default = " + rules.getDefaultPolicy());
            out.println();
            for (FirewallRule r : rules.getRules()) {
                out.println(r.getId() + " | " + r.getType() + " | " + r.getCondition() + " | "
                        + r.getAction() + " | " + r.isEnabled());
            }
        } catch (IOException ex) {
            dialog("Couldn't save the rules", ex.getMessage(), true, "OK", null);
            return;
        }
        dirty = false;
        updateStatus();
        toast("Rules saved to " + RULES_FILE.toAbsolutePath(), GREEN, "save");
    }

    private void loadRules() {
        try {
            rules = Files.exists(RULES_FILE) ? RuleManager.loadFromFile(RULES_FILE) : RuleManager.defaults();
        } catch (IOException e) {
            startupWarning = e.getMessage();
            rules = RuleManager.defaults();
        }
    }

    // =================================================================
    //  Server control and live updates
    // =================================================================
    private void toggleProtection() {
        if (running) {
            server.stop();
            running = false;
            updateStatus();
            toast("Protection stopped. Clients can no longer connect.", AMBER, "power");
            return;
        }
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
            if (port < 1 || port > 65535) throw new NumberFormatException();
        } catch (NumberFormatException e) {
            dialog("Invalid port", "Enter a port number between 1 and 65535.", true, "OK", null);
            return;
        }
        TCP_Server s = new TCP_Server(port, new FirewallEngine(rules), logger);
        server = s;
        running = true;
        runningPort = port;
        startedAt = System.currentTimeMillis();
        updateStatus();
        toast("Protection enabled on port " + port, GREEN, "check");

        Thread t = new Thread(() -> {
            try {
                s.start();
            } catch (IOException e) {
                SwingUtilities.invokeLater(() -> dialog("Couldn't start the firewall",
                        "Port " + port + " could not be opened:\n" + e.getMessage()
                                + "\n\nAnother program, or another copy of Firewall Shield, may already be using this port.",
                        true, "OK", null));
            } finally {
                if (server == s) {
                    running = false;
                    SwingUtilities.invokeLater(this::updateStatus);
                }
            }
        }, "firewall-server");
        t.setDaemon(true);
        t.start();
    }

    private void updateStatus() {
        boolean on = running;
        ring.setProtected(on);
        portField.setEnabled(!on);
        if (on) {
            heroTitle.setText("You're protected");
            heroSub.setText("Firewall Shield is checking all traffic on port " + runningPort + ".");
            toggleBtn.setText("Stop protection");
            toggleBtn.setKind(Kind.DANGER_SOFT);
            headerPill.set("Protected", GREEN);
            sidePill.set("Protected", GREEN);
            sideDetail.setText("Listening on port " + runningPort);
            statusLeft.setIcon(new VIcon("dot", 8, GREEN));
            statusLeft.setText("Engine running  ·  port " + runningPort);
        } else {
            heroTitle.setText("Protection is off");
            heroSub.setText("Start protection so clients can connect and their traffic is filtered.");
            toggleBtn.setText("Start protection");
            toggleBtn.setKind(Kind.SUCCESS);
            headerPill.set("Not protected", RED);
            sidePill.set("Not protected", RED);
            sideDetail.setText("Engine stopped");
            statusLeft.setIcon(new VIcon("dot", 8, RED));
            statusLeft.setText("Engine stopped");
        }

        List<FirewallRule> list = rules.getRules();
        long enabled = list.stream().filter(FirewallRule::isEnabled).count();
        rulesVal.setText(enabled + " of " + list.size());
        Action policy = rules.getDefaultPolicy();
        policyVal.setText(policy == Action.ALLOW ? "Allow" : "Block");
        policyVal.setForeground(policy == Action.ALLOW ? GREEN : RED);
        policySeg.setSelectedSilently(policy == Action.ALLOW ? 0 : 1);

        saveBtn.setText(dirty ? "Save changes" : "Saved");
        saveBtn.setKind(dirty ? Kind.SUCCESS : Kind.GHOST);
        statusRight.setText(enabled + " active rules  ·  logs/firewall.log"
                + (dirty ? "  ·  Unsaved rule changes" : "") + "  ·  v" + VERSION);
    }

    /** Called from server threads by the logger. */
    private void onLogEntry(String time, String ip, String action, String reason, String summary) {
        if ("ALLOW".equals(action)) { allowed.incrementAndGet(); secAllowed.incrementAndGet(); }
        if ("BLOCK".equals(action)) { blocked.incrementAndGet(); secBlocked.incrementAndGet(); }
        if (summary.isEmpty() && !"INFO".equals(action)) connections.incrementAndGet(); // connection check
        SwingUtilities.invokeLater(() -> {
            activityModel.insertRow(0, new Object[]{time, ip, action, reason, summary});
            if (activityModel.getRowCount() > 1000) activityModel.removeRow(1000);
            if ("BLOCK".equals(action)) {
                threatModel.add(0, new String[]{time.length() > 11 ? time.substring(11) : time, ip, reason});
                if (threatModel.size() > 50) threatModel.remove(50);
            }
        });
    }

    /** Runs once a second on the Swing thread. */
    private void tick() {
        chart.push(secAllowed.getAndSet(0), secBlocked.getAndSet(0));
        allowedCard.set(String.format("%,d", allowed.get()), chart.sumAllowed() + " in the last minute");
        blockedCard.set(String.format("%,d", blocked.get()), chart.sumBlocked() + " in the last minute");
        connCard.set(String.format("%,d", connections.get()), "since the app started");
        int active = running && server != null ? server.getActiveClients() : 0;
        activeCard.set(String.valueOf(active), active == 1 ? "client connected now" : "clients connected now");

        if (running) {
            long s = (System.currentTimeMillis() - startedAt) / 1000;
            uptimeVal.setText(String.format("%02d:%02d:%02d", s / 3600, (s / 60) % 60, s % 60));
        } else {
            uptimeVal.setText("-");
        }
        clockLbl.setText(LocalDateTime.now().format(DateTimeFormatter.ofPattern("EEE d MMM  ·  HH:mm")));
    }

    // =================================================================
    //  Dialogs and toasts
    // =================================================================
    private FirewallRule ruleDialog(FirewallRule existing, int id) {
        JDialog d = new JDialog(this, true);
        d.setUndecorated(true);
        JPanel root = new JPanel(new BorderLayout(0, 20));
        root.setBackground(SURFACE);
        root.setBorder(new CompoundBorder(new LineBorder(BORDER_HI), new EmptyBorder(22, 24, 20, 24)));

        JPanel head = new JPanel(new BorderLayout(14, 0));
        head.setOpaque(false);
        head.add(new Badge(existing == null ? "plus" : "edit", ACCENT, 40), BorderLayout.WEST);
        head.add(cardTitle(existing == null ? "New rule" : "Edit rule", "Rule ID #" + id
                + "  ·  rules are checked in list order"), BorderLayout.CENTER);
        root.add(head, BorderLayout.NORTH);

        JPanel form = vbox();
        Segmented typeSeg = new Segmented(new String[]{"Keyword", "IP address"},
                existing != null && existing.getType() == FirewallRule.Type.IP ? 1 : 0, null);
        StyledField cond = new StyledField(null, "");
        cond.setPreferredSize(new Dimension(400, 38));
        cond.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        if (existing != null) cond.setText(existing.getCondition());
        JLabel hint = label(" ", font(12), SUBTLE);
        Segmented actSeg = new Segmented(new String[]{"Allow", "Block"},
                existing != null && existing.getAction() == Action.ALLOW ? 0 : 1, null);
        actSeg.setAccent(i -> i == 0 ? GREEN : RED);
        JLabel error = label(" ", font(12), RED);

        Runnable typeChanged = () -> {
            boolean ip = typeSeg.getSelected() == 1;
            cond.setPlaceholder(ip ? "e.g. 192.168.1.20" : "e.g. DROP TABLE");
            hint.setText(ip ? "Matches when the client's IP address is exactly this address."
                    : "Matches when the message contains this text (upper/lower case is ignored).");
            cond.repaint();
        };
        typeSeg.setOnChange(i -> typeChanged.run());
        typeChanged.run();

        form.add(fieldLabel("Rule type"));
        form.add(typeSeg);
        form.add(Box.createVerticalStrut(16));
        form.add(fieldLabel("Condition"));
        form.add(cond);
        form.add(Box.createVerticalStrut(6));
        form.add(hint);
        form.add(Box.createVerticalStrut(16));
        form.add(fieldLabel("Action"));
        form.add(actSeg);
        form.add(Box.createVerticalStrut(12));
        form.add(error);
        for (Component c : form.getComponents()) ((JComponent) c).setAlignmentX(LEFT_ALIGNMENT);
        root.add(form, BorderLayout.CENTER);

        final FirewallRule[] result = new FirewallRule[1];
        FlatButton cancel = new FlatButton("Cancel", null, Kind.GHOST);
        cancel.addActionListener(e -> d.dispose());
        FlatButton ok = new FlatButton(existing == null ? "Create rule" : "Save changes", "check", Kind.PRIMARY);
        ok.addActionListener(e -> {
            String c = cond.getText().trim();
            boolean ip = typeSeg.getSelected() == 1;
            if (c.isEmpty()) { error.setText("Enter a condition."); return; }
            if (c.contains("|")) { error.setText("The condition can't contain the '|' character."); return; }
            if (ip && !isIpAddress(c)) { error.setText("Enter a valid IP address, e.g. 192.168.1.20"); return; }
            try {
                result[0] = new FirewallRule(id, ip ? FirewallRule.Type.IP : FirewallRule.Type.KEYWORD, c,
                        actSeg.getSelected() == 0 ? Action.ALLOW : Action.BLOCK,
                        existing == null || existing.isEnabled());
                d.dispose();
            } catch (IllegalArgumentException ex) {
                error.setText(ex.getMessage());
            }
        });
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        buttons.setOpaque(false);
        buttons.add(cancel);
        buttons.add(Box.createHorizontalStrut(10));
        buttons.add(ok);
        root.add(buttons, BorderLayout.SOUTH);

        showDialog(d, root, ok);
        return result[0];
    }

    private static boolean isIpAddress(String s) {
        String octet = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
        return s.matches("^(" + octet + "\\.){3}" + octet + "$")
                || (s.contains(":") && s.matches("^[0-9a-fA-F:.]+$"));
    }

    /** Styled message box. Returns true if the main button was pressed. */
    private boolean dialog(String title, String message, boolean danger, String okText, String cancelText) {
        JDialog d = new JDialog(this, true);
        d.setUndecorated(true);
        JPanel root = new JPanel(new BorderLayout(16, 0));
        root.setBackground(SURFACE);
        root.setBorder(new CompoundBorder(new LineBorder(BORDER_HI), new EmptyBorder(22, 22, 18, 24)));
        Color c = danger ? RED : ACCENT;
        JPanel bw = new JPanel(new BorderLayout());
        bw.setOpaque(false);
        bw.add(new Badge(danger ? "block" : "info", c, 40), BorderLayout.NORTH);
        root.add(bw, BorderLayout.WEST);

        JPanel body = vbox();
        body.add(label(title, semi(16), TEXT));
        body.add(Box.createVerticalStrut(8));
        JTextArea ta = new JTextArea(message);
        ta.setEditable(false);
        ta.setLineWrap(true);
        ta.setWrapStyleWord(true);
        ta.setOpaque(false);
        ta.setForeground(MUTED);
        ta.setFont(font(13));
        ta.setBorder(null);
        ta.setSize(new Dimension(380, 1000));
        ta.setPreferredSize(new Dimension(380, ta.getPreferredSize().height));
        body.add(ta);
        body.add(Box.createVerticalStrut(20));

        final boolean[] result = {false};
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        buttons.setOpaque(false);
        if (cancelText != null) {
            FlatButton cancel = new FlatButton(cancelText, null, Kind.GHOST);
            cancel.addActionListener(e -> d.dispose());
            buttons.add(cancel);
            buttons.add(Box.createHorizontalStrut(10));
        }
        FlatButton ok = new FlatButton(okText, null, danger && cancelText != null ? Kind.DANGER : Kind.PRIMARY);
        ok.addActionListener(e -> { result[0] = true; d.dispose(); });
        buttons.add(ok);
        body.add(buttons);
        for (Component comp : body.getComponents()) ((JComponent) comp).setAlignmentX(LEFT_ALIGNMENT);
        root.add(body, BorderLayout.CENTER);

        showDialog(d, root, ok);
        return result[0];
    }

    private void showDialog(JDialog d, JPanel root, JButton defaultButton) {
        d.setContentPane(root);
        d.getRootPane().setDefaultButton(defaultButton);
        d.getRootPane().registerKeyboardAction(e -> d.dispose(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);
        Point[] drag = new Point[1];
        root.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { drag[0] = e.getPoint(); }
        });
        root.addMouseMotionListener(new MouseMotionAdapter() {
            @Override public void mouseDragged(MouseEvent e) {
                Point p = d.getLocation();
                d.setLocation(p.x + e.getX() - drag[0].x, p.y + e.getY() - drag[0].y);
            }
        });
        d.pack();
        d.setLocationRelativeTo(this);
        d.setVisible(true);
    }

    private void toast(String message, Color color, String icon) {
        JLayeredPane lp = getLayeredPane();
        if (toast != null) {
            lp.remove(toast);
            lp.repaint();
        }
        RoundPanel t = new RoundPanel(12, SURFACE3, BORDER_HI);
        t.setLayout(new BorderLayout());
        t.setBorder(new EmptyBorder(12, 14, 12, 18));
        JLabel l = label(message, font(13), TEXT);
        l.setIcon(new VIcon(icon, 16, color));
        l.setIconTextGap(10);
        t.add(l);
        Dimension d = t.getPreferredSize();
        t.setBounds(lp.getWidth() - d.width - 24, lp.getHeight() - d.height - 50, d.width, d.height);
        lp.add(t, JLayeredPane.POPUP_LAYER);
        t.validate();
        lp.repaint();
        toast = t;
        if (toastTimer != null) toastTimer.stop();
        toastTimer = new Timer(2800, e -> {
            lp.remove(t);
            lp.repaint();
            if (toast == t) toast = null;
        });
        toastTimer.setRepeats(false);
        toastTimer.start();
    }

    // =================================================================
    //  Small builders
    // =================================================================
    static JPanel vbox() {
        JPanel p = new JPanel();
        p.setOpaque(false);
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        return p;
    }

    static JLabel label(String text, Font f, Color c) {
        JLabel l = new JLabel(text);
        l.setFont(f);
        l.setForeground(c);
        return l;
    }

    static JLabel fieldLabel(String text) {
        JLabel l = label(text, semi(12), MUTED);
        l.setBorder(new EmptyBorder(0, 0, 7, 0));
        return l;
    }

    static JPanel cardTitle(String title, String subtitle) {
        JPanel p = vbox();
        p.add(label(title, semi(15), TEXT));
        p.add(Box.createVerticalStrut(2));
        p.add(label(subtitle, font(12), MUTED));
        return p;
    }

    static JLabel legend(String text, Color c) {
        JLabel l = label(text, font(12), MUTED);
        l.setIcon(new VIcon("dot", 9, c));
        l.setIconTextGap(7);
        return l;
    }

    static Color alpha(Color c, int a) {
        return new Color(c.getRed(), c.getGreen(), c.getBlue(), Math.max(0, Math.min(255, a)));
    }

    static Graphics2D smooth(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
        g2.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        return g2;
    }

    static String ellipsize(FontMetrics fm, String s, int max) {
        if (fm.stringWidth(s) <= max) return s;
        String dots = "...";
        int end = s.length();
        while (end > 0 && fm.stringWidth(s.substring(0, end) + dots) > max) end--;
        return s.substring(0, end) + dots;
    }

    static void paintEmptyState(JComponent c, Graphics g, String icon, String title, String sub) {
        Graphics2D g2 = smooth(g);
        int cx = c.getWidth() / 2;
        int cy = Math.max(70, c.getHeight() / 2 - 10);
        g2.setColor(SURFACE2);
        g2.fill(new Ellipse2D.Double(cx - 28, cy - 62, 56, 56));
        new VIcon(icon, 26, SUBTLE).paintIcon(c, g2, cx - 13, cy - 47);
        g2.setFont(semi(14));
        FontMetrics fm = g2.getFontMetrics();
        g2.setColor(MUTED);
        g2.drawString(title, cx - fm.stringWidth(title) / 2, cy + 14);
        g2.setFont(font(12));
        fm = g2.getFontMetrics();
        g2.setColor(SUBTLE);
        g2.drawString(sub, cx - fm.stringWidth(sub) / 2, cy + 34);
        g2.dispose();
    }

    static JScrollPane scroll(JComponent c) {
        JScrollPane sp = new JScrollPane(c);
        sp.setBorder(BorderFactory.createEmptyBorder());
        sp.setViewportBorder(null);
        sp.setBackground(SURFACE);
        sp.getViewport().setBackground(SURFACE);
        for (JScrollBar sb : new JScrollBar[]{sp.getVerticalScrollBar(), sp.getHorizontalScrollBar()}) {
            sb.setUI(new SlimScrollBarUI());
            sb.setBackground(SURFACE);
            sb.setUnitIncrement(16);
        }
        sp.getVerticalScrollBar().setPreferredSize(new Dimension(10, 0));
        sp.getHorizontalScrollBar().setPreferredSize(new Dimension(0, 10));
        JPanel corner = new JPanel();
        corner.setBackground(SURFACE);
        sp.setCorner(ScrollPaneConstants.UPPER_RIGHT_CORNER, corner);
        return sp;
    }

    static JComponent tableCard(JTable t) {
        RoundPanel card = new RoundPanel(16, SURFACE, BORDER);
        card.setLayout(new BorderLayout());
        card.setBorder(new EmptyBorder(6, 6, 6, 6));
        card.add(scroll(t));
        return card;
    }

    static void styleTable(JTable t) {
        t.setBackground(SURFACE);
        t.setForeground(TEXT);
        t.setShowGrid(false);
        t.setIntercellSpacing(new Dimension(0, 0));
        t.setRowHeight(44);
        t.setFont(font(13));
        t.setSelectionBackground(SELECT);
        t.setSelectionForeground(TEXT);
        t.setFillsViewportHeight(true);
        t.setDefaultRenderer(Object.class, new CellRenderer(font(13), TEXT));

        JTableHeader h = t.getTableHeader();
        h.setReorderingAllowed(false);
        h.setBackground(SURFACE);
        h.setBorder(null);
        h.setDefaultRenderer((tbl, v, s, f, r, c) -> {
            JLabel l = label(String.valueOf(v).toUpperCase(), semi(11), SUBTLE);
            l.setOpaque(true);
            l.setBackground(SURFACE);
            l.setBorder(new CompoundBorder(new MatteBorder(0, 0, 1, 0, BORDER), new EmptyBorder(0, 14, 0, 8)));
            l.setPreferredSize(new Dimension(l.getPreferredSize().width, 40));
            return l;
        });

        t.addMouseMotionListener(new MouseMotionAdapter() {
            @Override public void mouseMoved(MouseEvent e) {
                int row = t.rowAtPoint(e.getPoint());
                Object old = t.getClientProperty("hoverRow");
                if (!(old instanceof Integer) || (Integer) old != row) {
                    t.putClientProperty("hoverRow", row);
                    t.repaint();
                }
            }
        });
        t.addMouseListener(new MouseAdapter() {
            @Override public void mouseExited(MouseEvent e) {
                t.putClientProperty("hoverRow", -1);
                t.repaint();
            }
        });
    }

    static Color rowBg(JTable t, int row, boolean selected) {
        if (selected) return SELECT;
        Object h = t.getClientProperty("hoverRow");
        if (h instanceof Integer && (Integer) h == row) return HOVER;
        return SURFACE;
    }

    static BufferedImage appIcon(int s) {
        BufferedImage img = new BufferedImage(s, s, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2 = smooth(img.getGraphics());
        g2.setPaint(new GradientPaint(0, 0, new Color(0x6AA6FF), s, s, new Color(0x2B5BD0)));
        g2.fill(new RoundRectangle2D.Double(0, 0, s, s, s * 0.32, s * 0.32));
        int is = (int) Math.round(s * 0.66);
        int off = (s - is) / 2;
        new VIcon("shield", is, Color.WHITE, 2.2f).paintIcon(null, g2, off, off);
        int ks = (int) Math.round(s * 0.30);
        new VIcon("check", ks, Color.WHITE, 3.2f).paintIcon(null, g2, (s - ks) / 2, (s - ks) / 2);
        g2.dispose();
        return img;
    }

    // =================================================================
    //  Custom components
    // =================================================================

    /** Vector line icons drawn on a 24x24 grid, so they stay sharp at any size. */
    static class VIcon implements Icon {
        private final String kind;
        private final int size;
        private final Color color;
        private final float stroke;

        VIcon(String kind, int size, Color color) { this(kind, size, color, 2f); }
        VIcon(String kind, int size, Color color, float stroke) {
            this.kind = kind; this.size = size; this.color = color; this.stroke = stroke;
        }
        @Override public int getIconWidth()  { return size; }
        @Override public int getIconHeight() { return size; }

        @Override public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = smooth(g);
            g2.translate(x, y);
            g2.scale(size / 24.0, size / 24.0);
            g2.setColor(color);
            g2.setStroke(new BasicStroke(stroke, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            switch (kind) {
                case "dashboard" -> {
                    rect(g2, 3, 3, 8, 8); rect(g2, 13, 3, 8, 8); rect(g2, 3, 13, 8, 8); rect(g2, 13, 13, 8, 8);
                }
                case "activity" -> poly(g2, 2, 12, 6, 12, 9, 4, 15, 20, 18, 12, 22, 12);
                case "rules" -> {
                    line(g2, 9, 6, 21, 6); line(g2, 9, 12, 21, 12); line(g2, 9, 18, 21, 18);
                    dot(g2, 4, 6, 1.6); dot(g2, 4, 12, 1.6); dot(g2, 4, 18, 1.6);
                }
                case "shield" -> {
                    Path2D p = new Path2D.Double();
                    p.moveTo(12, 2.5); p.lineTo(19.5, 5.5); p.lineTo(19.5, 11);
                    p.curveTo(19.5, 16, 16.2, 19.8, 12, 21.5);
                    p.curveTo(7.8, 19.8, 4.5, 16, 4.5, 11);
                    p.lineTo(4.5, 5.5); p.closePath();
                    g2.draw(p);
                }
                case "check" -> poly(g2, 5, 12.5, 10, 17.5, 19, 7);
                case "x", "clear" -> { line(g2, 6, 6, 18, 18); line(g2, 18, 6, 6, 18); }
                case "block" -> { g2.draw(new Ellipse2D.Double(3, 3, 18, 18)); line(g2, 5.8, 5.8, 18.2, 18.2); }
                case "network" -> {
                    g2.draw(new Ellipse2D.Double(9.5, 2.5, 5, 5));
                    g2.draw(new Ellipse2D.Double(2.5, 16.5, 5, 5));
                    g2.draw(new Ellipse2D.Double(16.5, 16.5, 5, 5));
                    line(g2, 10.8, 7.2, 6.2, 16.6); line(g2, 13.2, 7.2, 17.8, 16.6); line(g2, 7.5, 19, 16.5, 19);
                }
                case "users" -> {
                    g2.draw(new Ellipse2D.Double(8, 3, 8, 8));
                    g2.draw(new Arc2D.Double(4, 14, 16, 14, 0, 180, Arc2D.OPEN));
                }
                case "search" -> { g2.draw(new Ellipse2D.Double(4, 4, 12, 12)); line(g2, 14.5, 14.5, 20, 20); }
                case "plus" -> { line(g2, 12, 5, 12, 19); line(g2, 5, 12, 19, 12); }
                case "trash" -> {
                    line(g2, 4, 7, 20, 7); line(g2, 10, 3.5, 14, 3.5);
                    g2.draw(new RoundRectangle2D.Double(6, 7, 12, 13.5, 3, 3));
                    line(g2, 10, 11, 10, 16.5); line(g2, 14, 11, 14, 16.5);
                }
                case "up" -> poly(g2, 6, 15, 12, 9, 18, 15);
                case "down" -> poly(g2, 6, 9, 12, 15, 18, 9);
                case "save" -> {
                    g2.draw(new RoundRectangle2D.Double(4, 4, 16, 16, 4, 4));
                    poly(g2, 8, 4, 8, 9, 15, 9, 15, 4); line(g2, 8, 15, 16, 15);
                }
                case "export" -> {
                    line(g2, 12, 3, 12, 15); poly(g2, 7, 10, 12, 15, 17, 10); poly(g2, 4, 16, 4, 20, 20, 20, 20, 16);
                }
                case "power" -> { g2.draw(new Arc2D.Double(4, 5, 16, 16, 125, 290, Arc2D.OPEN)); line(g2, 12, 3, 12, 11); }
                case "edit" -> { poly(g2, 4, 20, 4, 16, 15, 5, 19, 9, 8, 20, 4, 20); line(g2, 13, 7, 17, 11); }
                case "info" -> { g2.draw(new Ellipse2D.Double(3, 3, 18, 18)); line(g2, 12, 11, 12, 16.5); dot(g2, 12, 7.8, 1.3); }
                case "clock" -> { g2.draw(new Ellipse2D.Double(3, 3, 18, 18)); poly(g2, 12, 7, 12, 12, 15.5, 14); }
                case "dot" -> dot(g2, 12, 12, 11);
                default -> { }
            }
            g2.dispose();
        }

        private static void line(Graphics2D g, double x1, double y1, double x2, double y2) {
            g.draw(new Line2D.Double(x1, y1, x2, y2));
        }
        private static void rect(Graphics2D g, double x, double y, double w, double h) {
            g.draw(new RoundRectangle2D.Double(x, y, w, h, 3, 3));
        }
        private static void dot(Graphics2D g, double cx, double cy, double r) {
            g.fill(new Ellipse2D.Double(cx - r, cy - r, r * 2, r * 2));
        }
        private static void poly(Graphics2D g, double... p) {
            Path2D path = new Path2D.Double();
            path.moveTo(p[0], p[1]);
            for (int i = 2; i < p.length; i += 2) path.lineTo(p[i], p[i + 1]);
            g.draw(path);
        }
    }

    static class RoundPanel extends JPanel {
        private final int arc;
        private final Color fill, line;
        RoundPanel(int arc, Color fill, Color line) {
            this.arc = arc; this.fill = fill; this.line = line;
            setOpaque(false);
        }
        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            g2.setColor(fill);
            g2.fill(new RoundRectangle2D.Double(0, 0, getWidth() - 1, getHeight() - 1, arc, arc));
            if (line != null) {
                g2.setColor(line);
                g2.draw(new RoundRectangle2D.Double(0.5, 0.5, getWidth() - 2, getHeight() - 2, arc, arc));
            }
            g2.dispose();
        }
    }

    /** Icon in a tinted rounded square. */
    static class Badge extends JComponent {
        private final String icon;
        private final Color color;
        private final int size;
        Badge(String icon, Color color, int size) {
            this.icon = icon; this.color = color; this.size = size;
            setPreferredSize(new Dimension(size, size));
        }
        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            g2.setColor(alpha(color, 36));
            g2.fill(new RoundRectangle2D.Double(0, 0, size, size, 12, 12));
            int is = size / 2;
            new VIcon(icon, is, color).paintIcon(this, g2, (size - is) / 2, (size - is) / 2);
            g2.dispose();
        }
    }

    enum Kind { PRIMARY, SUCCESS, DANGER, DANGER_SOFT, GHOST }

    static class FlatButton extends JButton {
        private Kind kind;
        private final String icon;
        private boolean hover, press;

        FlatButton(String text, String icon, Kind kind) {
            super(text);
            this.icon = icon;
            this.kind = kind;
            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setOpaque(false);
            setFont(semi(13));
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            addMouseListener(new MouseAdapter() {
                @Override public void mouseEntered(MouseEvent e)  { hover = true;  repaint(); }
                @Override public void mouseExited(MouseEvent e)   { hover = false; press = false; repaint(); }
                @Override public void mousePressed(MouseEvent e)  { press = true;  repaint(); }
                @Override public void mouseReleased(MouseEvent e) { press = false; repaint(); }
            });
        }

        void setKind(Kind k) { kind = k; repaint(); }

        private Color fg() {
            return switch (kind) {
                case GHOST -> TEXT;
                case DANGER_SOFT -> RED;
                default -> Color.WHITE;
            };
        }

        @Override public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(getFont());
            String t = getText();
            int tw = t == null || t.isEmpty() ? 0 : fm.stringWidth(t);
            int iw = icon == null ? 0 : 16;
            if (tw == 0) return new Dimension(38, 38);
            return new Dimension(tw + iw + (iw > 0 ? 8 : 0) + 34, 38);
        }
        @Override public Dimension getMaximumSize() { return getPreferredSize(); }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            if (!isEnabled()) g2.setComposite(AlphaComposite.SrcOver.derive(0.4f));
            boolean hot = hover && isEnabled();
            int w = getWidth(), h = getHeight();
            Shape shape = new RoundRectangle2D.Double(0, 0, w - 1, h - 1, 10, 10);
            switch (kind) {
                case GHOST -> {
                    g2.setColor(press && hot ? SURFACE3 : hot ? new Color(0x222C39) : SURFACE2);
                    g2.fill(shape);
                    g2.setColor(BORDER_HI);
                    g2.draw(shape);
                }
                case DANGER_SOFT -> {
                    g2.setColor(alpha(RED, hot ? 52 : 30));
                    g2.fill(shape);
                    g2.setColor(alpha(RED, 90));
                    g2.draw(shape);
                }
                default -> {
                    Color base = kind == Kind.PRIMARY ? ACCENT : kind == Kind.SUCCESS ? GREEN : RED;
                    if (press && hot) base = base.darker();
                    else if (hot) base = blend(base, Color.WHITE, 0.12f);
                    g2.setPaint(new GradientPaint(0, 0, blend(base, Color.WHITE, 0.06f), 0, h, base));
                    g2.fill(shape);
                }
            }
            FontMetrics fm = g2.getFontMetrics(getFont());
            String t = getText() == null ? "" : getText();
            int tw = t.isEmpty() ? 0 : fm.stringWidth(t);
            int iw = icon == null ? 0 : 16;
            int gap = iw > 0 && tw > 0 ? 8 : 0;
            int x = (w - (iw + gap + tw)) / 2;
            Color fg = fg();
            if (icon != null) {
                new VIcon(icon, 16, fg).paintIcon(this, g2, x, (h - 16) / 2);
                x += iw + gap;
            }
            g2.setFont(getFont());
            g2.setColor(fg);
            g2.drawString(t, x, (h + fm.getAscent() - fm.getDescent()) / 2);
            g2.dispose();
        }

        private static Color blend(Color a, Color b, float t) {
            return new Color((int) (a.getRed() + (b.getRed() - a.getRed()) * t),
                    (int) (a.getGreen() + (b.getGreen() - a.getGreen()) * t),
                    (int) (a.getBlue() + (b.getBlue() - a.getBlue()) * t));
        }
    }

    /** Segmented control (a row of mutually exclusive options). */
    static class Segmented extends JComponent {
        private final String[] options;
        private int selected;
        private IntConsumer onChange;
        private IntFunction<Color> accent;

        Segmented(String[] options, int selected, IntConsumer onChange) {
            this.options = options;
            this.selected = selected;
            this.onChange = onChange;
            setFont(semi(12));
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            addMouseListener(new MouseAdapter() {
                @Override public void mousePressed(MouseEvent e) {
                    int i = indexAt(e.getX());
                    if (i >= 0 && i != Segmented.this.selected) setSelected(i);
                }
            });
        }
        void setAccent(IntFunction<Color> accent) { this.accent = accent; repaint(); }
        void setOnChange(IntConsumer onChange) { this.onChange = onChange; }
        int getSelected() { return selected; }
        void setSelected(int i) {
            selected = i;
            repaint();
            if (onChange != null) onChange.accept(i);
        }
        void setSelectedSilently(int i) { selected = i; repaint(); }

        private int segWidth(int i) { return getFontMetrics(getFont()).stringWidth(options[i]) + 30; }
        private int indexAt(int x) {
            int x0 = 4;
            for (int i = 0; i < options.length; i++) {
                int w = segWidth(i);
                if (x >= x0 && x < x0 + w) return i;
                x0 += w;
            }
            return -1;
        }
        @Override public Dimension getPreferredSize() {
            int w = 8;
            for (int i = 0; i < options.length; i++) w += segWidth(i);
            return new Dimension(w, 38);
        }
        @Override public Dimension getMaximumSize() { return getPreferredSize(); }
        @Override public Dimension getMinimumSize() { return getPreferredSize(); }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int w = getPreferredSize().width, h = getHeight();
            g2.setColor(SURFACE2);
            g2.fill(new RoundRectangle2D.Double(0, 0, w - 1, h - 1, 10, 10));
            g2.setColor(BORDER_HI);
            g2.draw(new RoundRectangle2D.Double(0.5, 0.5, w - 2, h - 2, 10, 10));
            g2.setFont(getFont());
            FontMetrics fm = g2.getFontMetrics();
            int x0 = 4;
            for (int i = 0; i < options.length; i++) {
                int sw = segWidth(i);
                Color a = accent == null ? null : accent.apply(i);
                Color fg = MUTED;
                if (i == selected) {
                    g2.setColor(a == null ? SURFACE3 : alpha(a, 46));
                    g2.fill(new RoundRectangle2D.Double(x0, 4, sw, h - 8, 7, 7));
                    fg = a == null ? TEXT : a;
                }
                g2.setColor(fg);
                g2.drawString(options[i], x0 + (sw - fm.stringWidth(options[i])) / 2,
                        (h + fm.getAscent() - fm.getDescent()) / 2);
                x0 += sw;
            }
            g2.dispose();
        }
    }

    static class StyledField extends JTextField {
        private final String icon;
        private String placeholder;

        StyledField(String icon, String placeholder) {
            this.icon = icon;
            this.placeholder = placeholder;
            setOpaque(false);
            setFont(font(13));
            setForeground(TEXT);
            setDisabledTextColor(MUTED);
            setCaretColor(TEXT);
            setSelectionColor(SELECT);
            setSelectedTextColor(TEXT);
            setBorder(new EmptyBorder(9, icon == null ? 12 : 36, 9, 12));
            addFocusListener(new FocusAdapter() {
                @Override public void focusGained(FocusEvent e) { repaint(); }
                @Override public void focusLost(FocusEvent e)   { repaint(); }
            });
        }
        void setPlaceholder(String p) { placeholder = p; repaint(); }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int w = getWidth(), h = getHeight();
            g2.setColor(isEnabled() ? SURFACE2 : SURFACE);
            g2.fill(new RoundRectangle2D.Double(0, 0, w - 1, h - 1, 10, 10));
            g2.setColor(hasFocus() ? ACCENT : BORDER_HI);
            g2.draw(new RoundRectangle2D.Double(0.5, 0.5, w - 2, h - 2, 10, 10));
            if (icon != null) new VIcon(icon, 16, MUTED).paintIcon(this, g2, 12, (h - 16) / 2);
            g2.dispose();
            super.paintComponent(g);
            if (getText().isEmpty() && placeholder != null && !placeholder.isEmpty()) {
                Graphics2D p = smooth(g);
                p.setFont(getFont());
                p.setColor(SUBTLE);
                FontMetrics fm = p.getFontMetrics();
                p.drawString(placeholder, getInsets().left, (h + fm.getAscent() - fm.getDescent()) / 2);
                p.dispose();
            }
        }
    }

    static class NavItem extends JComponent {
        private final String name, icon;
        private boolean selected, hover;

        NavItem(String name, String icon, Runnable onClick) {
            this.name = name;
            this.icon = icon;
            setPreferredSize(new Dimension(200, 42));
            setMaximumSize(new Dimension(Integer.MAX_VALUE, 42));
            setAlignmentX(LEFT_ALIGNMENT);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            addMouseListener(new MouseAdapter() {
                @Override public void mouseEntered(MouseEvent e) { hover = true;  repaint(); }
                @Override public void mouseExited(MouseEvent e)  { hover = false; repaint(); }
                @Override public void mousePressed(MouseEvent e) { onClick.run(); }
            });
        }
        void setSelected(boolean s) { selected = s; repaint(); }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int w = getWidth(), h = getHeight();
            if (selected) {
                g2.setColor(SURFACE2);
                g2.fill(new RoundRectangle2D.Double(0, 0, w, h, 10, 10));
                g2.setColor(ACCENT);
                g2.fill(new RoundRectangle2D.Double(0, 11, 3, h - 22, 3, 3));
            } else if (hover) {
                g2.setColor(HOVER);
                g2.fill(new RoundRectangle2D.Double(0, 0, w, h, 10, 10));
            }
            Color c = selected || hover ? TEXT : MUTED;
            new VIcon(icon, 18, selected ? ACCENT : c).paintIcon(this, g2, 16, (h - 18) / 2);
            g2.setFont(selected ? semi(14) : font(14));
            g2.setColor(c);
            FontMetrics fm = g2.getFontMetrics();
            g2.drawString(name, 46, (h + fm.getAscent() - fm.getDescent()) / 2);
            g2.dispose();
        }
    }

    static class StatusPill extends JComponent {
        private String text = " ";
        private Color color = MUTED;

        StatusPill() { setFont(semi(12)); }
        void set(String t, Color c) {
            text = t; color = c;
            revalidate(); repaint();
        }
        @Override public Dimension getPreferredSize() {
            return new Dimension(getFontMetrics(getFont()).stringWidth(text) + 36, 28);
        }
        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int w = getPreferredSize().width, h = 28;
            g2.setColor(alpha(color, 30));
            g2.fill(new RoundRectangle2D.Double(0, 0, w - 1, h - 1, h, h));
            g2.setColor(alpha(color, 85));
            g2.draw(new RoundRectangle2D.Double(0.5, 0.5, w - 2, h - 2, h, h));
            g2.setColor(alpha(color, 60));
            g2.fill(new Ellipse2D.Double(9, h / 2.0 - 6, 12, 12));
            g2.setColor(color);
            g2.fill(new Ellipse2D.Double(12, h / 2.0 - 3, 6, 6));
            g2.setFont(getFont());
            FontMetrics fm = g2.getFontMetrics();
            g2.drawString(text, 26, (h + fm.getAscent() - fm.getDescent()) / 2);
            g2.dispose();
        }
    }

    static class StatCard extends RoundPanel {
        private final JLabel value, foot;

        StatCard(String title, String icon, Color color) {
            super(16, SURFACE, BORDER);
            setLayout(new BorderLayout(14, 0));
            setBorder(new EmptyBorder(16, 18, 16, 18));
            JPanel bw = new JPanel(new BorderLayout());
            bw.setOpaque(false);
            bw.add(new Badge(icon, color, 42), BorderLayout.NORTH);
            add(bw, BorderLayout.WEST);
            JPanel txt = vbox();
            txt.add(label(title, font(12), MUTED));
            txt.add(Box.createVerticalStrut(2));
            value = label("0", semi(26), TEXT);
            txt.add(value);
            foot = label(" ", font(11), SUBTLE);
            txt.add(foot);
            add(txt, BorderLayout.CENTER);
        }
        void set(String v, String f) {
            value.setText(v);
            foot.setText(f);
        }
    }

    /** Big animated status emblem on the dashboard. */
    static class ShieldRing extends JComponent {
        private boolean prot;
        private double phase;
        private final Timer anim = new Timer(40, e -> { phase += 0.04; repaint(); });

        ShieldRing() { setPreferredSize(new Dimension(164, 164)); }
        void setProtected(boolean p) {
            prot = p;
            if (p) anim.start(); else anim.stop();
            repaint();
        }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            double s = Math.min(getWidth(), getHeight());
            double cx = getWidth() / 2.0, cy = getHeight() / 2.0;
            Color c = prot ? GREEN : RED;

            float pulse = prot ? (float) (0.5 + 0.5 * Math.sin(phase * 2)) : 0.25f;
            g2.setPaint(new RadialGradientPaint(new Point2D.Double(cx, cy), (float) (s / 2),
                    new float[]{0.5f, 1f}, new Color[]{alpha(c, (int) (45 + 45 * pulse)), alpha(c, 0)}));
            g2.fill(new Ellipse2D.Double(cx - s / 2, cy - s / 2, s, s));

            double r = s / 2 - 16;
            Ellipse2D ringShape = new Ellipse2D.Double(cx - r, cy - r, 2 * r, 2 * r);
            g2.setStroke(new BasicStroke(7f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.setColor(SURFACE3);
            g2.draw(ringShape);
            if (prot) {
                g2.setColor(c);
                g2.draw(ringShape);
                double start = -(phase * 110) % 360;
                g2.setColor(alpha(Color.WHITE, 150));
                g2.draw(new Arc2D.Double(cx - r, cy - r, 2 * r, 2 * r, start, 46, Arc2D.OPEN));
            } else {
                g2.setColor(alpha(c, 170));
                g2.draw(new Arc2D.Double(cx - r, cy - r, 2 * r, 2 * r, 90, 250, Arc2D.OPEN));
            }

            double ir = r - 14;
            g2.setPaint(new GradientPaint((float) cx, (float) (cy - ir), c.brighter(),
                    (float) cx, (float) (cy + ir), c.darker().darker()));
            g2.fill(new Ellipse2D.Double(cx - ir, cy - ir, 2 * ir, 2 * ir));

            int is = (int) (ir * 1.15);
            new VIcon("shield", is, Color.WHITE, 1.7f).paintIcon(this, g2, (int) (cx - is / 2.0), (int) (cy - is / 2.0));
            int ks = (int) (is * 0.42);
            new VIcon(prot ? "check" : "x", ks, Color.WHITE, 3f)
                    .paintIcon(this, g2, (int) (cx - ks / 2.0), (int) (cy - ks / 2.0));
            g2.dispose();
        }
    }

    /** Area chart of allowed/blocked decisions per second. */
    static class TrafficChart extends JComponent {
        private static final int N = 60;
        private final int[] a = new int[N], b = new int[N];

        void push(int allowedNow, int blockedNow) {
            System.arraycopy(a, 1, a, 0, N - 1);
            System.arraycopy(b, 1, b, 0, N - 1);
            a[N - 1] = allowedNow;
            b[N - 1] = blockedNow;
            repaint();
        }
        int sumAllowed() { return Arrays.stream(a).sum(); }
        int sumBlocked() { return Arrays.stream(b).sum(); }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int left = 30, right = 6, top = 6, bottom = 22;
            int w = getWidth() - left - right, h = getHeight() - top - bottom;
            if (w < 20 || h < 20) { g2.dispose(); return; }
            int max = 4;
            for (int i = 0; i < N; i++) max = Math.max(max, Math.max(a[i], b[i]));
            max = ((max + 3) / 4) * 4;

            g2.setFont(font(11));
            FontMetrics fm = g2.getFontMetrics();
            Stroke dashed = new BasicStroke(1f, BasicStroke.CAP_BUTT, BasicStroke.JOIN_MITER, 10f, new float[]{3f, 4f}, 0f);
            for (int i = 0; i <= 4; i++) {
                int y = top + h - h * i / 4;
                g2.setStroke(i == 0 ? new BasicStroke(1f) : dashed);
                g2.setColor(i == 0 ? BORDER_HI : BORDER);
                g2.drawLine(left, y, left + w, y);
                String s = String.valueOf(max * i / 4);
                g2.setColor(SUBTLE);
                g2.drawString(s, left - 8 - fm.stringWidth(s), y + 4);
            }
            int ly = top + h + 16;
            g2.drawString("60s ago", left, ly);
            g2.drawString("30s", left + w / 2 - fm.stringWidth("30s") / 2, ly);
            g2.drawString("now", left + w - fm.stringWidth("now"), ly);

            series(g2, a, GREEN, left, top, w, h, max);
            series(g2, b, RED, left, top, w, h, max);
            g2.dispose();
        }

        private void series(Graphics2D g2, int[] v, Color c, int left, int top, int w, int h, int max) {
            Path2D line = new Path2D.Double();
            double lx = 0, ly = 0;
            for (int i = 0; i < N; i++) {
                double x = left + w * i / (double) (N - 1);
                double y = top + h - h * v[i] / (double) max;
                if (i == 0) line.moveTo(x, y); else line.lineTo(x, y);
                lx = x; ly = y;
            }
            Path2D area = new Path2D.Double(line);
            area.lineTo(left + w, top + h);
            area.lineTo(left, top + h);
            area.closePath();
            g2.setPaint(new GradientPaint(0, top, alpha(c, 70), 0, top + h, alpha(c, 0)));
            g2.fill(area);
            g2.setStroke(new BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.setColor(c);
            g2.draw(line);
            g2.setColor(alpha(c, 60));
            g2.fill(new Ellipse2D.Double(lx - 6, ly - 6, 12, 12));
            g2.setColor(c);
            g2.fill(new Ellipse2D.Double(lx - 3, ly - 3, 6, 6));
        }
    }

    static class ThreatRenderer extends JComponent implements ListCellRenderer<String[]> {
        private String time = "", ip = "", reason = "";

        ThreatRenderer() { setPreferredSize(new Dimension(10, 58)); }

        @Override public Component getListCellRendererComponent(JList<? extends String[]> list, String[] v,
                                                                int index, boolean sel, boolean focus) {
            time = v[0]; ip = v[1]; reason = v[2];
            return this;
        }
        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int w = getWidth(), h = getHeight();
            g2.setColor(SURFACE);
            g2.fillRect(0, 0, w, h);
            g2.setColor(ROWLINE);
            g2.fillRect(0, h - 1, w, 1);
            int bs = 34, by = (h - bs) / 2;
            g2.setColor(alpha(RED, 34));
            g2.fill(new RoundRectangle2D.Double(0, by, bs, bs, 10, 10));
            new VIcon("block", 16, RED).paintIcon(this, g2, (bs - 16) / 2, by + (bs - 16) / 2);

            int tx = bs + 12;
            g2.setFont(font(11));
            FontMetrics fm = g2.getFontMetrics();
            int tw = fm.stringWidth(time);
            g2.setColor(SUBTLE);
            g2.drawString(time, w - tw - 4, h / 2 - 4);
            g2.setFont(mono(13));
            g2.setColor(TEXT);
            g2.drawString(ellipsize(g2.getFontMetrics(), ip, w - tx - tw - 14), tx, h / 2 - 4);
            g2.setFont(font(12));
            g2.setColor(MUTED);
            g2.drawString(ellipsize(g2.getFontMetrics(), reason, w - tx - 6), tx, h / 2 + 14);
            g2.dispose();
        }
    }

    static class EmptyAwareTable extends JTable {
        private final String icon, title, sub;
        EmptyAwareTable(TableModel m, String icon, String title, String sub) {
            super(m);
            this.icon = icon; this.title = title; this.sub = sub;
        }
        @Override protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            if (getRowCount() == 0) paintEmptyState(this, g, icon, title, sub);
        }
    }

    static class CellRenderer extends DefaultTableCellRenderer {
        private final Font f;
        private final Color fg;
        CellRenderer(Font f, Color fg) { this.f = f; this.fg = fg; }

        @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean sel,
                                                                 boolean focus, int r, int c) {
            super.getTableCellRendererComponent(t, v, sel, false, r, c);
            setFont(f);
            setForeground(sel ? TEXT : fg);
            setBackground(rowBg(t, r, sel));
            setBorder(new CompoundBorder(new MatteBorder(0, 0, 1, 0, ROWLINE), new EmptyBorder(0, 14, 0, 10)));
            setToolTipText(v == null || String.valueOf(v).length() < 40 ? null : String.valueOf(v));
            return this;
        }
    }

    /** Coloured rounded tag inside a table cell. */
    static class PillRenderer extends JComponent implements TableCellRenderer {
        private final Function<Object, Color> colorFor;
        private final Function<Object, String> textFor;
        private String text = "";
        private Color color = MUTED, bg = SURFACE;

        PillRenderer(Function<Object, Color> colorFor, Function<Object, String> textFor) {
            this.colorFor = colorFor;
            this.textFor = textFor;
            setFont(semi(11));
        }
        @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean sel,
                                                                 boolean focus, int r, int c) {
            text = textFor.apply(v);
            color = colorFor.apply(v);
            bg = rowBg(t, r, sel);
            return this;
        }
        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int w = getWidth(), h = getHeight();
            g2.setColor(bg);
            g2.fillRect(0, 0, w, h);
            g2.setColor(ROWLINE);
            g2.fillRect(0, h - 1, w, 1);
            g2.setFont(getFont());
            FontMetrics fm = g2.getFontMetrics();
            int pw = fm.stringWidth(text) + 26, ph = 22, x = 14, y = (h - ph) / 2;
            g2.setColor(alpha(color, 34));
            g2.fill(new RoundRectangle2D.Double(x, y, pw, ph, ph, ph));
            g2.setColor(color);
            g2.fill(new Ellipse2D.Double(x + 9, h / 2.0 - 2.5, 5, 5));
            g2.drawString(text, x + 18, y + (ph + fm.getAscent() - fm.getDescent()) / 2);
            g2.dispose();
        }
    }

    /** On/off switch inside a table cell (click toggles; handled by the table's mouse listener). */
    static class SwitchRenderer extends JComponent implements TableCellRenderer {
        private boolean on;
        private Color bg = SURFACE;

        @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean sel,
                                                                 boolean focus, int r, int c) {
            on = Boolean.TRUE.equals(v);
            bg = rowBg(t, r, sel);
            return this;
        }
        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int w = getWidth(), h = getHeight();
            g2.setColor(bg);
            g2.fillRect(0, 0, w, h);
            g2.setColor(ROWLINE);
            g2.fillRect(0, h - 1, w, 1);
            int sw = 36, sh = 20, x = 14, y = (h - sh) / 2;
            g2.setColor(on ? GREEN : SURFACE3);
            g2.fill(new RoundRectangle2D.Double(x, y, sw, sh, sh, sh));
            g2.setColor(on ? Color.WHITE : MUTED);
            int k = sh - 6;
            g2.fill(new Ellipse2D.Double(on ? x + sw - k - 3 : x + 3, y + 3, k, k));
            g2.setFont(font(12));
            g2.setColor(on ? TEXT : SUBTLE);
            FontMetrics fm = g2.getFontMetrics();
            g2.drawString(on ? "Enabled" : "Disabled", x + sw + 10, (h + fm.getAscent() - fm.getDescent()) / 2);
            g2.dispose();
        }
    }

    static class SlimScrollBarUI extends BasicScrollBarUI {
        @Override protected JButton createDecreaseButton(int o) { return zeroButton(); }
        @Override protected JButton createIncreaseButton(int o) { return zeroButton(); }
        private static JButton zeroButton() {
            JButton b = new JButton();
            Dimension z = new Dimension(0, 0);
            b.setPreferredSize(z); b.setMinimumSize(z); b.setMaximumSize(z);
            return b;
        }
        @Override protected void paintTrack(Graphics g, JComponent c, Rectangle r) {
            g.setColor(SURFACE);
            g.fillRect(r.x, r.y, r.width, r.height);
        }
        @Override protected void paintThumb(Graphics g, JComponent c, Rectangle r) {
            if (r.isEmpty() || !scrollbar.isEnabled()) return;
            Graphics2D g2 = smooth(g);
            g2.setColor(isDragging || isThumbRollover() ? new Color(0x485668) : BORDER_HI);
            g2.fill(new RoundRectangle2D.Double(r.x + 2, r.y + 2, r.width - 4, r.height - 4, 6, 6));
            g2.dispose();
        }
    }

    // =================================================================
    //  Entry point
    // =================================================================
    public static void main(String[] args) {
        System.setProperty("awt.useSystemAAFontSettings", "on");
        System.setProperty("swing.aatext", "true");
        try {
            UIManager.put("swing.boldMetal", Boolean.FALSE);
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (Exception ignored) { }
        UIManager.put("Table.focusCellHighlightBorder", BorderFactory.createEmptyBorder());
        UIManager.put("ToolTip.background", SURFACE3);
        UIManager.put("ToolTip.foreground", TEXT);
        UIManager.put("ToolTip.border", new CompoundBorder(new LineBorder(BORDER_HI), new EmptyBorder(5, 8, 5, 8)));
        UIManager.put("ToolTip.font", font(12));
        UIManager.put("TextField.inactiveForeground", MUTED);
        SwingUtilities.invokeLater(() -> new FirewallGUI().setVisible(true));
    }
}
