package com.cybershield.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Domain entity representing an individual recorded security incident.
 */
public class Incident {

    private int id;
    private String description;
    private String source;
    private ThreatCategory category;
    private ThreatSeverity severity;
    private int riskScore;
    private String status;
    private String createdAt;
    private AnalysisReport analysisReport;

    public Incident(int id, String description, String source) {
        this.id = id;
        this.description = description;
        this.source = source == null || source.isBlank() ? "Not specified" : source.trim();
        this.status = "Open";
        this.createdAt = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    public ThreatCategory getCategory() { return category; }
    public void setCategory(ThreatCategory category) { this.category = category; }

    public ThreatSeverity getSeverity() { return severity; }
    public void setSeverity(ThreatSeverity severity) { this.severity = severity; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getCreatedAt() { return createdAt; }
    public void setCreatedAt(String createdAt) { this.createdAt = createdAt; }

    public AnalysisReport getAnalysisReport() { return analysisReport; }
    public void setAnalysisReport(AnalysisReport analysisReport) { this.analysisReport = analysisReport; }

    @Override
    public String toString() {
        return String.format("Incident #%d [%s - %s] (Risk: %d/100)", id, category, severity, riskScore);
    }
}
