package com.cybershield.view;

import com.cybershield.controller.IncidentController;
import com.cybershield.model.AnalysisReport;
import com.cybershield.model.Incident;
import com.cybershield.model.ThreatCategory;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;

/**
 * Main Application Dashboard Window for CyberShield AI Desktop Edition.
 * Features real-time telemetry stats, natural language input, 10-point analysis cards,
 * interactive checklists, and audit log history.
 */
public class CyberShieldMainFrame extends JFrame {

    private final IncidentController controller;

    // Telemetry Labels
    private JLabel totalCountLabel;
    private JLabel highCritCountLabel;
    private JLabel resolvedCountLabel;

    // Form Inputs
    private JTextArea descriptionArea;
    private JTextField sourceField;
    private JButton analyzeButton;
    private JButton clearButton;
    private JButton historyButton;

    // Results Dashboard
    private JPanel resultsPanel;
    private JLabel categoryValueLabel;
    private JLabel severityBadgeLabel;
    private JLabel riskScoreLabel;
    private JProgressBar riskProgressBar;
    private JTextArea summaryArea;
    private JTextArea dangerArea;
    private JPanel actionsPanel;
    private JButton downloadReportBtn;
    private Incident lastAnalyzedIncident;

    // Theme Palette
    private static final Color BG_DARK = new Color(7, 13, 24);
    private static final Color PANEL_BG = new Color(17, 30, 53);
    private static final Color PANEL_BORDER = new Color(30, 53, 87);
    private static final Color TEXT_MAIN = new Color(241, 245, 249);
    private static final Color TEXT_MUTED = new Color(148, 163, 184);
    private static final Color CYAN_ACCENT = new Color(0, 240, 255);
    private static final Color BLUE_PRIMARY = new Color(37, 99, 235);

    public CyberShieldMainFrame(IncidentController controller) {
        super("CyberShield AI — Cyber Incident Detection & Analysis (Java PBL Edition)");
        this.controller = controller;
        initUI();
        updateTelemetry();
    }

    private void initUI() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1150, 900);
        setMinimumSize(new Dimension(950, 750));
        setLocationRelativeTo(null);
        getContentPane().setBackground(BG_DARK);
        setLayout(new BorderLayout());

        // Header Navigation
        add(createHeaderPanel(), BorderLayout.NORTH);

        // Scrollable Body
        JPanel body = new JPanel();
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        body.setBackground(BG_DARK);
        body.setBorder(new EmptyBorder(16, 24, 24, 24));

        body.add(createTelemetryCards());
        body.add(Box.createVerticalStrut(18));
        body.add(createInputCard());
        body.add(Box.createVerticalStrut(18));

        resultsPanel = createResultsCard();
        resultsPanel.setVisible(false);
        body.add(resultsPanel);

        JScrollPane scrollPane = new JScrollPane(body);
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
                new EmptyBorder(14, 24, 14, 24)
        ));

        JLabel titleLabel = new JLabel("🛡️ CyberShield AI");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 22));
        titleLabel.setForeground(Color.WHITE);

        JLabel subTitle = new JLabel("AI-Based Cyber Incident Detection & Analysis System (Java OOP Edition)");
        subTitle.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        subTitle.setForeground(CYAN_ACCENT);

        JPanel titleGrp = new JPanel();
        titleGrp.setLayout(new BoxLayout(titleGrp, BoxLayout.Y_AXIS));
        titleGrp.setOpaque(false);
        titleGrp.add(titleLabel);
        titleGrp.add(subTitle);
        header.add(titleGrp, BorderLayout.WEST);

        historyButton = new JButton("📋 View Audit History");
        historyButton.setFont(new Font("Segoe UI", Font.BOLD, 12));
        historyButton.setBackground(new Color(24, 40, 70));
        historyButton.setForeground(Color.WHITE);
        historyButton.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(PANEL_BORDER, 1, true),
                new EmptyBorder(8, 14, 8, 14)
        ));
        historyButton.addActionListener(e -> {
            HistoryDialog dialog = new HistoryDialog(this, controller);
            dialog.setVisible(true);
            updateTelemetry();
        });
        header.add(historyButton, BorderLayout.EAST);

        return header;
    }

    private JPanel createTelemetryCards() {
        JPanel panel = new JPanel(new GridLayout(1, 3, 16, 0));
        panel.setOpaque(false);
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 90));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        totalCountLabel = new JLabel("0");
        totalCountLabel.setFont(new Font("Segoe UI", Font.BOLD, 26));
        totalCountLabel.setForeground(CYAN_ACCENT);
        panel.add(createMiniCard("TOTAL ANALYZED", totalCountLabel, new Color(56, 189, 248)));

        highCritCountLabel = new JLabel("0");
        highCritCountLabel.setFont(new Font("Segoe UI", Font.BOLD, 26));
        highCritCountLabel.setForeground(new Color(248, 113, 113));
        panel.add(createMiniCard("CRITICAL & HIGH THREATS", highCritCountLabel, new Color(239, 68, 68)));

        resolvedCountLabel = new JLabel("0");
        resolvedCountLabel.setFont(new Font("Segoe UI", Font.BOLD, 26));
        resolvedCountLabel.setForeground(new Color(52, 211, 153));
        panel.add(createMiniCard("RESOLVED INCIDENTS", resolvedCountLabel, new Color(16, 185, 129)));

        return panel;
    }

    private JPanel createMiniCard(String title, JLabel valueLabel, Color accentColor) {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(PANEL_BG);
        card.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(PANEL_BORDER, 1, true),
                new EmptyBorder(12, 16, 12, 16)
        ));

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(new Font("Segoe UI", Font.BOLD, 10));
        titleLbl.setForeground(TEXT_MUTED);
        card.add(titleLbl);
        card.add(Box.createVerticalStrut(4));
        card.add(valueLabel);
        return card;
    }

    private JPanel createInputCard() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(PANEL_BG);
        panel.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(PANEL_BORDER, 1, true),
                new EmptyBorder(20, 20, 20, 20)
        ));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel label = new JLabel("Describe the cybersecurity issue or suspicious activity you are experiencing:");
        label.setFont(new Font("Segoe UI", Font.BOLD, 15));
        label.setForeground(TEXT_MAIN);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(label);
        panel.add(Box.createVerticalStrut(10));

        // Chips
        JPanel chips = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        chips.setOpaque(false);
        chips.setAlignmentX(Component.LEFT_ALIGNMENT);

        String[][] examples = {
            {"👤 Instagram Takeover", "Someone logged into my Instagram account without my permission."},
            {"📧 Bank Phishing", "I received a suspicious email asking me to verify my bank account."},
            {"🔒 Ransomware Files", "My computer files suddenly became inaccessible and their extensions changed."},
            {"🔑 Clicked Unknown Link", "I clicked an unknown link and entered my password."},
            {"💻 Pop-ups & Slow Laptop", "My laptop is showing unusual pop-ups and running very slowly."},
            {"⚠️ Repeated Logins", "Someone is repeatedly trying to access my account."}
        };

        for (String[] ex : examples) {
            JButton chip = new JButton(ex[0]);
            chip.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            chip.setBackground(new Color(25, 45, 78));
            chip.setForeground(Color.WHITE);
            chip.setFocusPainted(false);
            chip.setBorder(BorderFactory.createCompoundBorder(
                    new LineBorder(new Color(45, 80, 130), 1, true),
                    new EmptyBorder(5, 10, 5, 10)
            ));
            chip.addActionListener(e -> descriptionArea.setText(ex[1]));
            chips.add(chip);
        }
        panel.add(chips);
        panel.add(Box.createVerticalStrut(10));

        descriptionArea = new JTextArea(4, 50);
        descriptionArea.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        descriptionArea.setLineWrap(true);
        descriptionArea.setWrapStyleWord(true);
        descriptionArea.setBackground(new Color(9, 18, 34));
        descriptionArea.setForeground(TEXT_MAIN);
        descriptionArea.setCaretColor(CYAN_ACCENT);
        descriptionArea.setBorder(new EmptyBorder(8, 8, 8, 8));

        JScrollPane scroll = new JScrollPane(descriptionArea);
        scroll.setBorder(new LineBorder(PANEL_BORDER, 1));
        scroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(scroll);
        panel.add(Box.createVerticalStrut(10));

        JLabel srcLabel = new JLabel("Affected platform, device, or sender (optional):");
        srcLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        srcLabel.setForeground(TEXT_MUTED);
        srcLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(srcLabel);

        sourceField = new JTextField();
        sourceField.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        sourceField.setBackground(new Color(9, 18, 34));
        sourceField.setForeground(TEXT_MAIN);
        sourceField.setCaretColor(CYAN_ACCENT);
        sourceField.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(PANEL_BORDER, 1),
                new EmptyBorder(6, 8, 6, 8)
        ));
        sourceField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 32));
        sourceField.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(sourceField);
        panel.add(Box.createVerticalStrut(14));

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        btnRow.setOpaque(false);
        btnRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        analyzeButton = new JButton("⚡ Analyze Incident (Java NLP Engine)");
        analyzeButton.setFont(new Font("Segoe UI", Font.BOLD, 14));
        analyzeButton.setBackground(BLUE_PRIMARY);
        analyzeButton.setForeground(Color.WHITE);
        analyzeButton.setFocusPainted(false);
        analyzeButton.setBorder(new EmptyBorder(10, 18, 10, 18));
        analyzeButton.addActionListener(this::onAnalyze);
        btnRow.add(analyzeButton);

        clearButton = new JButton("↺ Clear");
        clearButton.setBackground(new Color(25, 45, 75));
        clearButton.setForeground(TEXT_MUTED);
        clearButton.setFocusPainted(false);
        clearButton.setBorder(new EmptyBorder(10, 14, 10, 14));
        clearButton.addActionListener(e -> {
            descriptionArea.setText("");
            sourceField.setText("");
        });
        btnRow.add(clearButton);

        panel.add(btnRow);
        return panel;
    }

    private JPanel createResultsCard() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(PANEL_BG);
        panel.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(35, 70, 120), 1, true),
                new EmptyBorder(20, 20, 20, 20)
        ));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Top Row Badges
        JPanel topRow = new JPanel(new GridLayout(1, 3, 14, 0));
        topRow.setOpaque(false);
        topRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        categoryValueLabel = new JLabel("Category");
        categoryValueLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        categoryValueLabel.setForeground(Color.WHITE);
        topRow.add(createMiniCard("DETECTED INCIDENT CATEGORY", categoryValueLabel, CYAN_ACCENT));

        severityBadgeLabel = new JLabel("Severity");
        severityBadgeLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        topRow.add(createMiniCard("THREAT SEVERITY", severityBadgeLabel, Color.ORANGE));

        riskScoreLabel = new JLabel("0 / 100");
        riskScoreLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        riskScoreLabel.setForeground(CYAN_ACCENT);

        JPanel scoreCard = createMiniCard("DYNAMIC RISK SCORE", riskScoreLabel, Color.YELLOW);
        riskProgressBar = new JProgressBar(0, 100);
        riskProgressBar.setBackground(new Color(10, 20, 35));
        riskProgressBar.setBorder(null);
        scoreCard.add(Box.createVerticalStrut(4));
        scoreCard.add(riskProgressBar);
        topRow.add(scoreCard);

        panel.add(topRow);
        panel.add(Box.createVerticalStrut(14));

        panel.add(createSubHeader("1. Incident Summary:"));
        summaryArea = createDisplayArea();
        panel.add(summaryArea);
        panel.add(Box.createVerticalStrut(10));

        panel.add(createSubHeader("2. Why This Incident May Be Dangerous:"));
        dangerArea = createDisplayArea();
        panel.add(dangerArea);
        panel.add(Box.createVerticalStrut(12));

        panel.add(createSubHeader("3. Immediate Recommended Actions (Interactive Checklist):"));
        actionsPanel = new JPanel();
        actionsPanel.setLayout(new BoxLayout(actionsPanel, BoxLayout.Y_AXIS));
        actionsPanel.setOpaque(false);
        actionsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(actionsPanel);
        panel.add(Box.createVerticalStrut(14));

        JPanel bottomBtnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        bottomBtnRow.setOpaque(false);
        bottomBtnRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        downloadReportBtn = new JButton("📥 Export Full Incident Report (.txt)");
        downloadReportBtn.setFont(new Font("Segoe UI", Font.BOLD, 13));
        downloadReportBtn.setBackground(new Color(2, 132, 199));
        downloadReportBtn.setForeground(Color.WHITE);
        downloadReportBtn.setFocusPainted(false);
        downloadReportBtn.setBorder(new EmptyBorder(8, 16, 8, 16));
        downloadReportBtn.addActionListener(this::onExportClicked);
        bottomBtnRow.add(downloadReportBtn);

        panel.add(bottomBtnRow);
        panel.add(Box.createVerticalStrut(10));

        JLabel disclaimer = new JLabel("<html><i>⚠️ <b>System Notice:</b> This assessment is derived from user descriptions for incident triage and does not probe live external networks.</i></html>");
        disclaimer.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        disclaimer.setForeground(new Color(254, 240, 138));
        disclaimer.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(disclaimer);

        return panel;
    }

    private JLabel createSubHeader(String text) {
        JLabel lbl = new JLabel(text);
        lbl.setFont(new Font("Segoe UI", Font.BOLD, 14));
        lbl.setForeground(CYAN_ACCENT);
        lbl.setAlignmentX(Component.LEFT_ALIGNMENT);
        return lbl;
    }

    private JTextArea createDisplayArea() {
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

    private void onAnalyze(ActionEvent e) {
        String desc = descriptionArea.getText().trim();
        String src = sourceField.getText().trim();

        try {
            lastAnalyzedIncident = controller.processIncident(desc, src);
            displayResults(lastAnalyzedIncident);
            updateTelemetry();
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Input Validation", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void displayResults(Incident inc) {
        AnalysisReport report = inc.getAnalysisReport();

        categoryValueLabel.setText(inc.getCategory().getDisplayName());
        severityBadgeLabel.setText(inc.getSeverity().getDisplayName());
        severityBadgeLabel.setForeground(inc.getSeverity().getBadgeColor());

        riskScoreLabel.setText(inc.getRiskScore() + " / 100");
        riskProgressBar.setValue(inc.getRiskScore());
        riskProgressBar.setForeground(inc.getSeverity().getBadgeColor());

        summaryArea.setText(report.getSummary());
        dangerArea.setText(report.getWhyDangerous());

        actionsPanel.removeAll();
        for (String act : report.getImmediateActions()) {
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

    private void onExportClicked(ActionEvent e) {
        if (lastAnalyzedIncident == null) return;
        try {
            File exported = controller.exportReport(lastAnalyzedIncident, "reports");
            JOptionPane.showMessageDialog(this,
                    "Intelligence Report saved successfully:\n" + exported.getAbsolutePath(),
                    "Report Exported", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to export report: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void updateTelemetry() {
        totalCountLabel.setText(String.valueOf(controller.getTotalCount()));
        highCritCountLabel.setText(String.valueOf(controller.getCriticalHighCount()));
        resolvedCountLabel.setText(String.valueOf(controller.getResolvedCount()));
    }
}
