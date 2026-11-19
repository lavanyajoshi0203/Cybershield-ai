import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * CyberShield AI - Java Desktop GUI (Swing Edition)
 * Native Java frontend interface for cyber incident detection and dynamic analysis.
 * Connects seamlessly to the local CyberShield AI backend REST API.
 */
public class CyberShieldApp extends JFrame {

    // UI Components
    private JTextArea descriptionArea;
    private JTextField sourceField;
    private JButton analyzeButton;
    private JButton clearButton;
    private JLabel statusLabel;

    // Results Dashboard Panels
    private JPanel resultsPanel;
    private JLabel categoryValueLabel;
    private JLabel severityBadgeLabel;
    private JLabel riskScoreLabel;
    private JProgressBar riskProgressBar;
    private JTextArea summaryArea;
    private JTextArea dangerArea;
    private JPanel actionsPanel;

    private final HttpClient httpClient;
    private static final String API_URL = "http://127.0.0.1:5000/api/incidents";

    // Theme Colors
    private static final Color BG_DARK = new Color(7, 13, 24);
    private static final Color PANEL_BG = new Color(17, 30, 53);
    private static final Color PANEL_BORDER = new Color(30, 53, 87);
    private static final Color TEXT_MAIN = new Color(241, 245, 249);
    private static final Color TEXT_MUTED = new Color(148, 163, 184);
    private static final Color CYAN_ACCENT = new Color(0, 240, 255);
    private static final Color BLUE_PRIMARY = new Color(37, 99, 235);

    public CyberShieldApp() {
        super("🛡️ CyberShield AI — Incident Detection & Analysis (Java Desktop Edition)");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        initUI();
    }

    private void initUI() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1100, 850);
        setMinimumSize(new Dimension(900, 700));
        setLocationRelativeTo(null);
        getContentPane().setBackground(BG_DARK);
        setLayout(new BorderLayout());

        // 1. Navigation Header
        add(createHeaderPanel(), BorderLayout.NORTH);

        // 2. Main Scrollable Content
        JPanel mainContent = new JPanel();
        mainContent.setLayout(new BoxLayout(mainContent, BoxLayout.Y_AXIS));
        mainContent.setBackground(BG_DARK);
        mainContent.setBorder(new EmptyBorder(16, 24, 24, 24));

        mainContent.add(createInputSection());
        mainContent.add(Box.createVerticalStrut(20));

        resultsPanel = createResultsSection();
        resultsPanel.setVisible(false); // Hidden until user analyzes
        mainContent.add(resultsPanel);

        JScrollPane scrollPane = new JScrollPane(mainContent);
        scrollPane.setBorder(null);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        scrollPane.getViewport().setBackground(BG_DARK);
        add(scrollPane, BorderLayout.CENTER);
    }

    private JPanel createHeaderPanel() {
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(new Color(14, 28, 54));
        header.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, PANEL_BORDER),
                new EmptyBorder(16, 24, 16, 24)
        ));

        JLabel titleLabel = new JLabel("🛡️ CyberShield AI");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 22));
        titleLabel.setForeground(Color.WHITE);

        JLabel subtitleLabel = new JLabel("AI-Powered Cyber Incident Detection & Analysis (Java Swing UI)");
        subtitleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        subtitleLabel.setForeground(CYAN_ACCENT);

        JPanel textGroup = new JPanel();
        textGroup.setLayout(new BoxLayout(textGroup, BoxLayout.Y_AXIS));
        textGroup.setOpaque(false);
        textGroup.add(titleLabel);
        textGroup.add(subtitleLabel);
        header.add(textGroup, BorderLayout.WEST);

        JLabel statusBadge = new JLabel("● AI Engine Connected");
        statusBadge.setFont(new Font("Segoe UI", Font.BOLD, 12));
        statusBadge.setForeground(new Color(52, 211, 153));
        header.add(statusBadge, BorderLayout.EAST);

        return header;
    }

    private JPanel createInputSection() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(PANEL_BG);
        panel.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(PANEL_BORDER, 1, true),
                new EmptyBorder(20, 20, 20, 20)
        ));

        JLabel sectionTitle = new JLabel("Describe the Cybersecurity Issue or Suspicious Activity:");
        sectionTitle.setFont(new Font("Segoe UI", Font.BOLD, 16));
        sectionTitle.setForeground(TEXT_MAIN);
        sectionTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(sectionTitle);

        panel.add(Box.createVerticalStrut(10));

        // Example Prompts Toolbar
        JLabel exampleTitle = new JLabel("💡 Click an example scenario to test:");
        exampleTitle.setFont(new Font("Segoe UI", Font.ITALIC, 12));
        exampleTitle.setForeground(CYAN_ACCENT);
        exampleTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(exampleTitle);
        panel.add(Box.createVerticalStrut(6));

        JPanel chipsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        chipsPanel.setOpaque(false);
        chipsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        String[][] examples = {
            {"👤 Instagram Takeover", "Someone logged into my Instagram account without my permission."},
            {"📧 Bank Phishing", "I received a suspicious email asking me to verify my bank account."},
            {"🔒 Ransomware / Locked Files", "My computer files suddenly became inaccessible and their extensions changed."},
            {"🔑 Clicked Unknown Link", "I clicked an unknown link and entered my password."},
            {"💻 Slow Laptop & Pop-ups", "My laptop is showing unusual pop-ups and running very slowly."},
            {"⚠️ Repeated Login Attempts", "Someone is repeatedly trying to access my account."}
        };

        for (String[] ex : examples) {
            JButton chipBtn = new JButton(ex[0]);
            chipBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            chipBtn.setBackground(new Color(25, 45, 78));
            chipBtn.setForeground(Color.WHITE);
            chipBtn.setFocusPainted(false);
            chipBtn.setBorder(BorderFactory.createCompoundBorder(
                    new LineBorder(new Color(45, 80, 130), 1, true),
                    new EmptyBorder(5, 10, 5, 10)
            ));
            chipBtn.addActionListener(e -> descriptionArea.setText(ex[1]));
            chipsPanel.add(chipBtn);
        }
        panel.add(chipsPanel);
        panel.add(Box.createVerticalStrut(12));

        // Text Area
        descriptionArea = new JTextArea(4, 50);
        descriptionArea.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        descriptionArea.setLineWrap(true);
        descriptionArea.setWrapStyleWord(true);
        descriptionArea.setBackground(new Color(9, 18, 34));
        descriptionArea.setForeground(TEXT_MAIN);
        descriptionArea.setCaretColor(CYAN_ACCENT);
        descriptionArea.setBorder(new EmptyBorder(10, 10, 10, 10));

        JScrollPane textScroll = new JScrollPane(descriptionArea);
        textScroll.setBorder(new LineBorder(PANEL_BORDER, 1));
        textScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(textScroll);

        panel.add(Box.createVerticalStrut(12));

        // Source Field (Optional)
        JLabel sourceLabel = new JLabel("Affected device or platform info (optional):");
        sourceLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        sourceLabel.setForeground(TEXT_MUTED);
        sourceLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(sourceLabel);
        panel.add(Box.createVerticalStrut(4));

        sourceField = new JTextField();
        sourceField.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        sourceField.setBackground(new Color(9, 18, 34));
        sourceField.setForeground(TEXT_MAIN);
        sourceField.setCaretColor(CYAN_ACCENT);
        sourceField.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(PANEL_BORDER, 1),
                new EmptyBorder(6, 10, 6, 10)
        ));
        sourceField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));
        sourceField.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(sourceField);

        panel.add(Box.createVerticalStrut(16));

        // Action Buttons Row
        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        btnRow.setOpaque(false);
        btnRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        analyzeButton = new JButton("⚡ Analyze Incident");
        analyzeButton.setFont(new Font("Segoe UI", Font.BOLD, 14));
        analyzeButton.setBackground(BLUE_PRIMARY);
        analyzeButton.setForeground(Color.WHITE);
        analyzeButton.setFocusPainted(false);
        analyzeButton.setBorder(new EmptyBorder(10, 20, 10, 20));
        analyzeButton.addActionListener(this::onAnalyzeClicked);
        btnRow.add(analyzeButton);

        clearButton = new JButton("↺ Clear");
        clearButton.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        clearButton.setBackground(new Color(25, 45, 75));
        clearButton.setForeground(TEXT_MUTED);
        clearButton.setFocusPainted(false);
        clearButton.setBorder(new EmptyBorder(10, 16, 10, 16));
        clearButton.addActionListener(e -> {
            descriptionArea.setText("");
            sourceField.setText("");
            statusLabel.setText("");
        });
        btnRow.add(clearButton);

        statusLabel = new JLabel("");
        statusLabel.setFont(new Font("Segoe UI", Font.ITALIC, 13));
        statusLabel.setForeground(CYAN_ACCENT);
        btnRow.add(statusLabel);

        panel.add(btnRow);
        return panel;
    }

    private JPanel createResultsSection() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(PANEL_BG);
        panel.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(35, 70, 120), 1, true),
                new EmptyBorder(22, 22, 22, 22)
        ));

        // Result Title & Badges Row
        JPanel topRow = new JPanel(new GridLayout(1, 3, 16, 0));
        topRow.setOpaque(false);
        topRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Card 1: Category
        JPanel catCard = createSubCard("DETECTED CATEGORY");
        categoryValueLabel = new JLabel("Phishing Attack");
        categoryValueLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        categoryValueLabel.setForeground(Color.WHITE);
        catCard.add(categoryValueLabel);
        topRow.add(catCard);

        // Card 2: Severity
        JPanel sevCard = createSubCard("THREAT SEVERITY");
        severityBadgeLabel = new JLabel("High");
        severityBadgeLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        severityBadgeLabel.setForeground(new Color(251, 146, 60));
        sevCard.add(severityBadgeLabel);
        topRow.add(sevCard);

        // Card 3: Risk Score
        JPanel scoreCard = createSubCard("RISK SCORE (0-100)");
        riskScoreLabel = new JLabel("80 / 100");
        riskScoreLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        riskScoreLabel.setForeground(CYAN_ACCENT);
        scoreCard.add(riskScoreLabel);

        riskProgressBar = new JProgressBar(0, 100);
        riskProgressBar.setValue(80);
        riskProgressBar.setForeground(new Color(245, 158, 11));
        riskProgressBar.setBackground(new Color(15, 25, 45));
        riskProgressBar.setBorder(null);
        scoreCard.add(riskProgressBar);
        topRow.add(scoreCard);

        panel.add(topRow);
        panel.add(Box.createVerticalStrut(16));

        // Summary Card
        panel.add(createSectionHeader("Incident Summary:"));
        summaryArea = createReadOnlyTextArea();
        panel.add(summaryArea);
        panel.add(Box.createVerticalStrut(12));

        // Danger Explanation Card
        panel.add(createSectionHeader("Why This Incident May Be Dangerous:"));
        dangerArea = createReadOnlyTextArea();
        panel.add(dangerArea);
        panel.add(Box.createVerticalStrut(14));

        // Immediate Action Checklist
        panel.add(createSectionHeader("Immediate Recommended Actions (Checklist):"));
        actionsPanel = new JPanel();
        actionsPanel.setLayout(new BoxLayout(actionsPanel, BoxLayout.Y_AXIS));
        actionsPanel.setOpaque(false);
        actionsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(actionsPanel);
        panel.add(Box.createVerticalStrut(14));

        // Disclaimer Notice
        JLabel disclaimerLabel = new JLabel("<html><i>⚠️ <b>Notice:</b> This system analyzes the description only and cannot independently verify live compromised hardware.</i></html>");
        disclaimerLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        disclaimerLabel.setForeground(new Color(254, 240, 138));
        disclaimerLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(disclaimerLabel);

        return panel;
    }

    private JPanel createSubCard(String title) {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(new Color(11, 21, 39));
        card.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(PANEL_BORDER, 1, true),
                new EmptyBorder(10, 14, 10, 14)
        ));

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(new Font("Segoe UI", Font.BOLD, 10));
        titleLbl.setForeground(TEXT_MUTED);
        card.add(titleLbl);
        card.add(Box.createVerticalStrut(6));
        return card;
    }

    private JLabel createSectionHeader(String text) {
        JLabel lbl = new JLabel(text);
        lbl.setFont(new Font("Segoe UI", Font.BOLD, 14));
        lbl.setForeground(CYAN_ACCENT);
        lbl.setAlignmentX(Component.LEFT_ALIGNMENT);
        return lbl;
    }

    private JTextArea createReadOnlyTextArea() {
        JTextArea area = new JTextArea(2, 40);
        area.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBackground(new Color(11, 21, 39));
        area.setForeground(TEXT_MAIN);
        area.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(PANEL_BORDER, 1),
                new EmptyBorder(8, 10, 8, 10)
        ));
        area.setAlignmentX(Component.LEFT_ALIGNMENT);
        return area;
    }

    private void onAnalyzeClicked(ActionEvent e) {
        String description = descriptionArea.getText().trim();
        String source = sourceField.getText().trim();

        if (description.length() < 10) {
            JOptionPane.showMessageDialog(this,
                    "Please enter at least 10 characters describing the incident.",
                    "Input Too Brief", JOptionPane.WARNING_MESSAGE);
            return;
        }

        analyzeButton.setEnabled(false);
        statusLabel.setText("Analyzing incident through AI engine...");

        // Run HTTP request in background worker thread so GUI doesn't freeze
        SwingWorker<String, Void> worker = new SwingWorker<>() {
            @Override
            protected String doInBackground() throws Exception {
                String jsonInput = String.format("{\"description\": \"%s\", \"source\": \"%s\"}",
                        description.replace("\"", "\\\"").replace("\n", " "),
                        source.replace("\"", "\\\""));

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(API_URL))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(jsonInput))
                        .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200 || response.statusCode() == 201) {
                    return response.body();
                } else {
                    throw new RuntimeException("Server returned status: " + response.statusCode());
                }
            }

            @Override
            protected void done() {
                analyzeButton.setEnabled(true);
                statusLabel.setText("");
                try {
                    String jsonResponse = get();
                    displayResults(jsonResponse);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(CyberShieldApp.this,
                            "Failed to connect to backend server at http://127.0.0.1:5000\nEnsure 'python app.py' is running in the background.",
                            "Connection Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        };

        worker.execute();
    }

    private void displayResults(String json) {
        // Simple and robust JSON parsing for response
        String category = extractJsonValue(json, "incident_type");
        String severity = extractJsonValue(json, "severity");
        String scoreStr = extractJsonValue(json, "risk_score");
        String summary = extractJsonValue(json, "incident_summary");
        String danger = extractJsonValue(json, "why_dangerous");

        int score = 75;
        try { score = Integer.parseInt(scoreStr); } catch (Exception ignored) {}

        categoryValueLabel.setText(category.isEmpty() ? "Cyber Incident" : category);
        severityBadgeLabel.setText(severity.isEmpty() ? "Medium" : severity);
        riskScoreLabel.setText(score + " / 100");
        riskProgressBar.setValue(score);

        // Color coding by severity
        if ("Critical".equalsIgnoreCase(severity)) {
            severityBadgeLabel.setForeground(new Color(239, 68, 68));
            riskProgressBar.setForeground(new Color(239, 68, 68));
        } else if ("High".equalsIgnoreCase(severity)) {
            severityBadgeLabel.setForeground(new Color(249, 115, 22));
            riskProgressBar.setForeground(new Color(249, 115, 22));
        } else if ("Medium".equalsIgnoreCase(severity)) {
            severityBadgeLabel.setForeground(new Color(234, 179, 8));
            riskProgressBar.setForeground(new Color(234, 179, 8));
        } else {
            severityBadgeLabel.setForeground(new Color(16, 185, 129));
            riskProgressBar.setForeground(new Color(16, 185, 129));
        }

        summaryArea.setText(summary.isEmpty() ? "Incident classified and recorded." : summary);
        dangerArea.setText(danger.isEmpty() ? "Potential unauthorized compromise or exposure hazard." : danger);

        // Populate Action Checklist
        actionsPanel.removeAll();
        String[] defaultActions = {
            "Immediately disconnect affected device from network/Wi-Fi to prevent lateral spread.",
            "Change account password from a known-clean device using a strong unique passphrase.",
            "Enable Two-Factor Authentication (2FA) with an authenticator app.",
            "Inspect recent login sessions and revoke all unrecognized devices."
        };

        for (String act : defaultActions) {
            JCheckBox cb = new JCheckBox(" " + act);
            cb.setFont(new Font("Segoe UI", Font.PLAIN, 13));
            cb.setForeground(TEXT_MAIN);
            cb.setBackground(PANEL_BG);
            cb.setFocusPainted(false);
            actionsPanel.add(cb);
            actionsPanel.add(Box.createVerticalStrut(4));
        }

        resultsPanel.setVisible(true);
        resultsPanel.revalidate();
        resultsPanel.repaint();
    }

    private String extractJsonValue(String json, String key) {
        String pattern = "\"" + key + "\":\\s*\"?([^,\"}]+)\"?";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
        if (m.find()) {
            return m.group(1).trim();
        }
        return "";
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            CyberShieldApp app = new CyberShieldApp();
            app.setVisible(true);
        });
    }
}
