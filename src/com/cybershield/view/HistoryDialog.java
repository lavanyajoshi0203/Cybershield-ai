package com.cybershield.view;

import com.cybershield.controller.IncidentController;
import com.cybershield.model.Incident;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.util.List;

/**
 * Audit Log dialog displaying historical incidents with filtering, report viewing, and export.
 */
public class HistoryDialog extends JDialog {

    private final IncidentController controller;
    private JTable table;
    private DefaultTableModel tableModel;

    private static final Color BG_DARK = new Color(11, 21, 39);
    private static final Color PANEL_BG = new Color(17, 30, 53);
    private static final Color PANEL_BORDER = new Color(30, 53, 87);
    private static final Color CYAN_ACCENT = new Color(0, 240, 255);

    public HistoryDialog(Frame parent, IncidentController controller) {
        super(parent, "Incident Intelligence Audit History", true);
        this.controller = controller;
        initUI();
        refreshData();
    }

    private void initUI() {
        setSize(850, 500);
        setLocationRelativeTo(getParent());
        getContentPane().setBackground(BG_DARK);
        setLayout(new BorderLayout());

        // Header
        JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 12));
        header.setBackground(PANEL_BG);
        JLabel title = new JLabel("📋 Recorded Security Incidents & Audit Log");
        title.setFont(new Font("Segoe UI", Font.BOLD, 16));
        title.setForeground(Color.WHITE);
        header.add(title);
        add(header, BorderLayout.NORTH);

        // Table
        String[] columns = {"ID", "Category", "Severity", "Risk", "Status", "Date", "Source"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };

        table = new JTable(tableModel);
        table.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        table.setRowHeight(28);
        table.setBackground(new Color(9, 18, 34));
        table.setForeground(Color.WHITE);
        table.setGridColor(PANEL_BORDER);
        table.getTableHeader().setBackground(PANEL_BG);
        table.getTableHeader().setForeground(CYAN_ACCENT);
        table.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setBorder(new EmptyBorder(12, 16, 12, 16));
        scrollPane.getViewport().setBackground(BG_DARK);
        add(scrollPane, BorderLayout.CENTER);

        // Bottom Actions
        JPanel footer = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 12));
        footer.setBackground(PANEL_BG);

        JButton viewBtn = new JButton("View Full Report");
        viewBtn.setBackground(new Color(2, 132, 199));
        viewBtn.setForeground(Color.WHITE);
        viewBtn.addActionListener(e -> onViewReport());
        footer.add(viewBtn);

        JButton resolveBtn = new JButton("Resolve Selected");
        resolveBtn.setBackground(new Color(22, 163, 74));
        resolveBtn.setForeground(Color.WHITE);
        resolveBtn.addActionListener(e -> onResolveSelected());
        footer.add(resolveBtn);

        JButton exportBtn = new JButton("Export Report (.txt)");
        exportBtn.setBackground(new Color(37, 99, 235));
        exportBtn.setForeground(Color.WHITE);
        exportBtn.addActionListener(e -> onExportReport());
        footer.add(exportBtn);

        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dispose());
        footer.add(closeBtn);

        add(footer, BorderLayout.SOUTH);
    }

    public void refreshData() {
        tableModel.setRowCount(0);
        List<Incident> list = controller.getAllIncidents();
        for (Incident inc : list) {
            tableModel.addRow(new Object[]{
                "#" + inc.getId(),
                inc.getCategory().getDisplayName(),
                inc.getSeverity().getDisplayName(),
                inc.getRiskScore() + "/100",
                inc.getStatus(),
                inc.getCreatedAt(),
                inc.getSource()
            });
        }
    }

    private void onViewReport() {
        int row = table.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select an incident from the table.", "Select Incident", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        List<Incident> list = controller.getAllIncidents();
        if (row < list.size()) {
            Incident selected = list.get(row);
            JTextArea textArea = new JTextArea(selected.getAnalysisReport().getSummary() + "\n\n" +
                    "Immediate Actions:\n" + String.join("\n", selected.getAnalysisReport().getImmediateActions()));
            textArea.setEditable(false);
            textArea.setFont(new Font("Segoe UI", Font.PLAIN, 13));
            JScrollPane sp = new JScrollPane(textArea);
            sp.setPreferredSize(new Dimension(500, 300));
            JOptionPane.showMessageDialog(this, sp, "Incident #" + selected.getId() + " - " + selected.getCategory(), JOptionPane.PLAIN_MESSAGE);
        }
    }

    private void onResolveSelected() {
        int row = table.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select an incident to resolve.", "Select Incident", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        List<Incident> list = controller.getAllIncidents();
        if (row < list.size()) {
            controller.resolveIncident(list.get(row).getId());
            refreshData();
            JOptionPane.showMessageDialog(this, "Incident marked as Resolved.", "Success", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void onExportReport() {
        int row = table.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select an incident to export.", "Select Incident", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        List<Incident> list = controller.getAllIncidents();
        if (row < list.size()) {
            try {
                File file = controller.exportReport(list.get(row), "reports");
                JOptionPane.showMessageDialog(this, "Report exported to: " + file.getAbsolutePath(), "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
