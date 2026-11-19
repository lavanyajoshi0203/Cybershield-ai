package com.cybershield.repository;

import com.cybershield.model.Incident;
import com.cybershield.model.ThreatSeverity;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Repository layer managing incident persistence, audit logs, and status updates.
 */
public class IncidentRepository {

    private final List<Incident> incidents;
    private final AtomicInteger idGenerator;

    public IncidentRepository() {
        this.incidents = new ArrayList<>();
        this.idGenerator = new AtomicInteger(1001);
    }

    public Incident save(Incident incident) {
        if (incident.getId() <= 0) {
            incident.setId(idGenerator.getAndIncrement());
        }
        // Insert at beginning so newest appears first
        incidents.add(0, incident);
        return incident;
    }

    public List<Incident> findAll() {
        return Collections.unmodifiableList(new ArrayList<>(incidents));
    }

    public Optional<Incident> findById(int id) {
        return incidents.stream().filter(i -> i.getId() == id).findFirst();
    }

    public boolean updateStatus(int id, String newStatus) {
        Optional<Incident> opt = findById(id);
        if (opt.isPresent()) {
            opt.get().setStatus(newStatus);
            return true;
        }
        return false;
    }

    public boolean deleteById(int id) {
        return incidents.removeIf(i -> i.getId() == id);
    }

    public int countTotal() {
        return incidents.size();
    }

    public int countCriticalAndHigh() {
        return (int) incidents.stream()
                .filter(i -> i.getSeverity() == ThreatSeverity.CRITICAL || i.getSeverity() == ThreatSeverity.HIGH)
                .count();
    }

    public int countResolved() {
        return (int) incidents.stream()
                .filter(i -> "Resolved".equalsIgnoreCase(i.getStatus()))
                .count();
    }
}
