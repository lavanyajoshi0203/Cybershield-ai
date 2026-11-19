package com.cybershield.controller;

import com.cybershield.model.AnalysisReport;
import com.cybershield.model.Incident;
import com.cybershield.model.ThreatCategory;
import com.cybershield.repository.IncidentRepository;
import com.cybershield.service.IncidentClassifier;
import com.cybershield.service.ReportExportService;
import com.cybershield.service.RiskAssessmentService;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Controller orchestrating input validation, AI NLP classification,
 * risk computation, and repository persistence.
 */
public class IncidentController {

    private final IncidentClassifier classifier;
    private final RiskAssessmentService riskService;
    private final ReportExportService exportService;
    private final IncidentRepository repository;

    public IncidentController() {
        this.classifier = new IncidentClassifier();
        this.riskService = new RiskAssessmentService();
        this.exportService = new ReportExportService();
        this.repository = new IncidentRepository();
    }

    /**
     * Main intake processing: Classifies natural language description and generates 10-point report.
     */
    public Incident processIncident(String description, String source) {
        if (description == null || description.trim().length() < 10) {
            throw new IllegalArgumentException("Description must contain at least 10 characters detailing the incident.");
        }
        if (description.length() > 3000) {
            throw new IllegalArgumentException("Description exceeds maximum allowed limit (3000 characters).");
        }

        // 1. Natural Language Entity Extraction & Intent Classification
        Map<String, String> entities = classifier.extractEntities(description);
        ThreatCategory category = classifier.classify(description);

        // 2. Dynamic Risk & Severity Assessment (10-point report)
        AnalysisReport report = riskService.generateReport(description, source, category, entities);

        // 3. Create & Persist Incident Entity
        Incident incident = new Incident(0, description.trim(), source);
        incident.setCategory(category);
        incident.setSeverity(report.getSeverity());
        incident.setRiskScore(report.getRiskScore());
        incident.setAnalysisReport(report);

        return repository.save(incident);
    }

    public List<Incident> getAllIncidents() {
        return repository.findAll();
    }

    public boolean resolveIncident(int id) {
        return repository.updateStatus(id, "Resolved");
    }

    public boolean deleteIncident(int id) {
        return repository.deleteById(id);
    }

    public File exportReport(Incident incident, String path) throws IOException {
        return exportService.exportToFile(incident, path);
    }

    public int getTotalCount() { return repository.countTotal(); }
    public int getCriticalHighCount() { return repository.countCriticalAndHigh(); }
    public int getResolvedCount() { return repository.countResolved(); }
}
