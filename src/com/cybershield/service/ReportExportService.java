package com.cybershield.service;

import com.cybershield.model.AnalysisReport;
import com.cybershield.model.Incident;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Service to format and export structured Incident Intelligence reports to disk.
 */
public class ReportExportService {

    public String generateReportText(Incident incident) {
        AnalysisReport report = incident.getAnalysisReport();
        StringBuilder sb = new StringBuilder();

        sb.append("======================================================================\n");
        sb.append("CYBERSHIELD AI - CYBERSECURITY INCIDENT INTELLIGENCE REPORT\n");
        sb.append("======================================================================\n");
        sb.append(String.format("Report ID:          INC-%05d\n", incident.getId()));
        sb.append(String.format("Timestamp:          %s\n", incident.getCreatedAt()));
        sb.append(String.format("Detected Category:  %s\n", incident.getCategory().getDisplayName()));
        sb.append(String.format("Threat Severity:    %s\n", incident.getSeverity().getDisplayName()));
        sb.append(String.format("Risk Score:         %d / 100\n", incident.getRiskScore()));
        sb.append(String.format("Reported Source:    %s\n", incident.getSource()));
        sb.append(String.format("Incident Status:    %s\n", incident.getStatus()));
        sb.append("----------------------------------------------------------------------\n");
        sb.append("1. USER REPORTED DESCRIPTION:\n   ").append(incident.getDescription()).append("\n\n");

        if (report != null) {
            sb.append("2. INCIDENT SUMMARY:\n   ").append(report.getSummary()).append("\n\n");
            sb.append("3. WHY THIS INCIDENT MAY BE DANGEROUS:\n   ").append(report.getWhyDangerous()).append("\n\n");

            sb.append("4. POSSIBLE ATTACK VECTORS:\n");
            for (String vec : report.getAttackVectors()) {
                sb.append("   • ").append(vec).append("\n");
            }
            sb.append("\n");

            sb.append("5. POTENTIAL IMPACT:\n");
            for (String imp : report.getPotentialImpacts()) {
                sb.append("   • ").append(imp).append("\n");
            }
            sb.append("\n");

            sb.append("6. IMMEDIATE RECOMMENDED ACTIONS (ACTION CHECKLIST):\n");
            for (String act : report.getImmediateActions()) {
                sb.append("   [ ] ").append(act).append("\n");
            }
            sb.append("\n");

            sb.append("7. LONG-TERM PREVENTION MEASURES:\n");
            for (String prev : report.getPreventionMeasures()) {
                sb.append("   • ").append(prev).append("\n");
            }
            sb.append("\n");

            sb.append("8. SECURITY RECOMMENDATIONS:\n");
            for (String rec : report.getRecommendations()) {
                sb.append("   • ").append(rec).append("\n");
            }
            sb.append("\n");

            sb.append("----------------------------------------------------------------------\n");
            sb.append("SYSTEM VERIFICATION & TRIAGE NOTICE:\n");
            sb.append(report.getDisclaimer()).append("\n");
        }
        sb.append("======================================================================\n");

        return sb.toString();
    }

    public File exportToFile(Incident incident, String directoryPath) throws IOException {
        String reportText = generateReportText(incident);
        File dir = new File(directoryPath);
        if (!dir.exists()) dir.mkdirs();

        File file = new File(dir, "cybershield_incident_" + incident.getId() + ".txt");
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(reportText);
        }
        return file;
    }
}
