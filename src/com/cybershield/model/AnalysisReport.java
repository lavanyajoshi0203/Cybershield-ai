package com.cybershield.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Domain model representing the dynamic 10-point cybersecurity intelligence report.
 */
public class AnalysisReport {

    private ThreatCategory category;
    private ThreatSeverity severity;
    private int riskScore;
    private String summary;
    private String whyDangerous;
    private List<String> attackVectors;
    private List<String> potentialImpacts;
    private List<String> immediateActions;
    private List<String> preventionMeasures;
    private List<String> recommendations;
    private String disclaimer;

    public AnalysisReport() {
        this.attackVectors = new ArrayList<>();
        this.potentialImpacts = new ArrayList<>();
        this.immediateActions = new ArrayList<>();
        this.preventionMeasures = new ArrayList<>();
        this.recommendations = new ArrayList<>();
        this.disclaimer = "This system analyzes the user's description only and cannot independently verify whether an actual account, device, or network was compromised.";
    }

    public ThreatCategory getCategory() { return category; }
    public void setCategory(ThreatCategory category) { this.category = category; }

    public ThreatSeverity getSeverity() { return severity; }
    public void setSeverity(ThreatSeverity severity) { this.severity = severity; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }

    public String getWhyDangerous() { return whyDangerous; }
    public void setWhyDangerous(String whyDangerous) { this.whyDangerous = whyDangerous; }

    public List<String> getAttackVectors() { return attackVectors; }
    public void setAttackVectors(List<String> attackVectors) { this.attackVectors = attackVectors; }

    public List<String> getPotentialImpacts() { return potentialImpacts; }
    public void setPotentialImpacts(List<String> potentialImpacts) { this.potentialImpacts = potentialImpacts; }

    public List<String> getImmediateActions() { return immediateActions; }
    public void setImmediateActions(List<String> immediateActions) { this.immediateActions = immediateActions; }

    public List<String> getPreventionMeasures() { return preventionMeasures; }
    public void setPreventionMeasures(List<String> preventionMeasures) { this.preventionMeasures = preventionMeasures; }

    public List<String> getRecommendations() { return recommendations; }
    public void setRecommendations(List<String> recommendations) { this.recommendations = recommendations; }

    public String getDisclaimer() { return disclaimer; }
    public void setDisclaimer(String disclaimer) { this.disclaimer = disclaimer; }
}
