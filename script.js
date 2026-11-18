/**
 * CyberShield AI - Frontend Application Controller
 * Handles natural language incident analysis, dynamic 10-point intelligence rendering,
 * interactive action checklists, metrics telemetry, and historical report audit.
 */

document.addEventListener("DOMContentLoaded", function () {
    // Form and input elements
    const form = document.getElementById("incidentForm");
    const descriptionInput = document.getElementById("description");
    const sourceInput = document.getElementById("source");
    const charCounter = document.getElementById("charCounter");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const clearInputBtn = document.getElementById("clearInputBtn");
    const message = document.getElementById("message");
    const loadingIndicator = document.getElementById("loadingIndicator");

    // Results Dashboard elements
    const resultsSection = document.getElementById("resultsSection");
    const resultCategoryTitle = document.getElementById("resultCategoryTitle");
    const categoryCardText = document.getElementById("categoryCardText");
    const severityBadge = document.getElementById("severityBadge");
    const riskScoreVal = document.getElementById("riskScoreVal");
    const riskScoreBar = document.getElementById("riskScoreBar");
    const summaryText = document.getElementById("summaryText");
    const dangerText = document.getElementById("dangerText");
    const attackVectorsList = document.getElementById("attackVectorsList");
    const potentialImpactList = document.getElementById("potentialImpactList");
    const immediateActionsChecklist = document.getElementById("immediateActionsChecklist");
    const preventionList = document.getElementById("preventionList");
    const recommendationsList = document.getElementById("recommendationsList");
    const downloadReportBtn = document.getElementById("downloadReportBtn");
    const analyzeAnotherBtn = document.getElementById("analyzeAnotherBtn");

    // History & Filter elements
    const tableBody = document.getElementById("incidentTableBody");
    const searchInput = document.getElementById("searchIncident");
    const riskFilter = document.getElementById("riskFilter");
    const statusFilter = document.getElementById("statusFilter");

    // Modal elements
    const reportModal = document.getElementById("reportModal");
    const modalTitle = document.getElementById("modalTitle");
    const modalBody = document.getElementById("modalBody");
    const closeModalBtn = document.getElementById("closeModalBtn");
    const modalCloseActionBtn = document.getElementById("modalCloseActionBtn");
    const modalDownloadBtn = document.getElementById("modalDownloadBtn");

    // Application state
    let incidents = [];
    let loading = false;
    let currentIncidentId = null;
    let modalCurrentId = null;

    const API_URL = "/api/incidents";

    // ----------------------------------------------------
    // Utility & Notification Helpers
    // ----------------------------------------------------
    function showMessage(text, isError = false) {
        if (!text) {
            message.style.display = "none";
            message.textContent = "";
            return;
        }
        message.textContent = text;
        message.style.display = "block";
        message.className = isError ? "alert-box alert-error" : "alert-box alert-success";
    }

    function clearMessage() {
        showMessage("");
    }

    function getSeverityClass(sev) {
        const s = (sev || "").toLowerCase();
        if (s === "critical") return "sev-critical";
        if (s === "high") return "sev-high";
        if (s === "medium") return "sev-medium";
        return "sev-low";
    }

    // Update character counter
    function updateCharCounter() {
        const len = descriptionInput.value.length;
        charCounter.textContent = `${len} / 3000`;
        if (len > 3000) {
            charCounter.style.color = "#f87171";
        } else if (len < 10 && len > 0) {
            charCounter.style.color = "#f59e0b";
        } else {
            charCounter.style.color = "";
        }
    }

    descriptionInput.addEventListener("input", updateCharCounter);

    // ----------------------------------------------------
    // Example Prompts Selection
    // ----------------------------------------------------
    document.querySelectorAll(".example-chip").forEach(function (chip) {
        chip.addEventListener("click", function () {
            const prompt = chip.getAttribute("data-prompt");
            if (prompt) {
                descriptionInput.value = prompt;
                updateCharCounter();
                clearMessage();
                descriptionInput.focus();
                descriptionInput.scrollIntoView({ behavior: "smooth", block: "center" });
            }
        });
    });

    // Clear input button
    clearInputBtn.addEventListener("click", function () {
        descriptionInput.value = "";
        sourceInput.value = "";
        updateCharCounter();
        clearMessage();
        descriptionInput.focus();
    });

    // ----------------------------------------------------
    // Incident Data Loading & Formatting
    // ----------------------------------------------------
    function formatIncident(record) {
        let date = record.created_at || "";
        if (date) {
            const parsed = new Date(date);
            if (!Number.isNaN(parsed.getTime())) {
                date = parsed.toLocaleString(undefined, {
                    month: "short",
                    day: "numeric",
                    hour: "2-digit",
                    minute: "2-digit"
                });
            }
        }

        const severity = record.severity || record.risk_level || "Medium";
        const riskScore = record.risk_score !== undefined && record.risk_score !== null
            ? record.risk_score
            : (severity === "Critical" ? 90 : (severity === "High" ? 75 : 50));

        return {
            id: record.id,
            type: record.incident_type,
            description: record.description,
            source: record.source,
            severity: severity,
            riskScore: riskScore,
            status: record.status,
            date: date,
            rawDate: record.created_at,
            analysis: record.analysis
        };
    }

    async function loadIncidents() {
        loading = true;
        try {
            const response = await fetch(API_URL);
            if (!response.ok) throw new Error("Could not load incidents.");

            const data = await response.json();
            incidents = data.map(formatIncident);

            refreshDashboard();
            renderIncidents();
        } catch (error) {
            console.error("Fetch error:", error);
            showMessage("Unable to load incidents. Please verify that the Flask server is running.", true);
        } finally {
            loading = false;
        }
    }

    // ----------------------------------------------------
    // Dashboard Counters & Telemetry Charts
    // ----------------------------------------------------
    function updateDashboard() {
        document.getElementById("totalIncidents").textContent = incidents.length;

        const highOrCrit = incidents.filter(function (item) {
            const s = (item.severity || "").toLowerCase();
            return s === "high" || s === "critical";
        }).length;
        document.getElementById("highRisk").textContent = highOrCrit;

        const resolvedCount = incidents.filter(function (item) {
            return item.status === "Resolved";
        }).length;
        document.getElementById("resolved").textContent = resolvedCount;
    }

    function updateChart() {
        const critical = incidents.filter(i => (i.severity || "").toLowerCase() === "critical").length;
        const high = incidents.filter(i => (i.severity || "").toLowerCase() === "high").length;
        const medium = incidents.filter(i => (i.severity || "").toLowerCase() === "medium").length;
        const low = incidents.filter(i => (i.severity || "").toLowerCase() === "low").length;

        const maxCount = Math.max(critical, high, medium, low, 1);

        document.getElementById("criticalCount").textContent = critical;
        document.getElementById("highCount").textContent = high;
        document.getElementById("mediumCount").textContent = medium;
        document.getElementById("lowCount").textContent = low;

        document.getElementById("criticalBar").style.width = (critical / maxCount * 100) + "%";
        document.getElementById("highBar").style.width = (high / maxCount * 100) + "%";
        document.getElementById("mediumBar").style.width = (medium / maxCount * 100) + "%";
        document.getElementById("lowBar").style.width = (low / maxCount * 100) + "%";

        document.getElementById("chartMessage").textContent = incidents.length === 0
            ? "No incident records found. Submit an incident above to populate telemetry."
            : `Analytics calculated from ${incidents.length} recorded security event(s).`;
    }

    function refreshDashboard() {
        updateDashboard();
        updateChart();
    }

    // ----------------------------------------------------
    // Render 10-Item Intelligence Dashboard
    // ----------------------------------------------------
    function renderAnalysisResult(result) {
        const analysis = result.analysis || {};
        currentIncidentId = result.id;

        // 1. Detected Incident Category
        const category = analysis.incident_category || result.incident_type || "Cyber Incident";
        resultCategoryTitle.textContent = category;
        categoryCardText.textContent = category;

        // 2. Threat Severity
        const severity = analysis.threat_severity || result.severity || result.risk_level || "Medium";
        severityBadge.textContent = severity;
        severityBadge.className = `severity-badge ${getSeverityClass(severity)}`;

        // 3. Risk Score (0-100)
        const score = analysis.risk_score !== undefined ? analysis.risk_score : 70;
        riskScoreVal.textContent = score;
        riskScoreBar.style.width = score + "%";
        if (score >= 85) {
            riskScoreBar.style.backgroundColor = "#ef4444";
        } else if (score >= 70) {
            riskScoreBar.style.backgroundColor = "#f59e0b";
        } else if (score >= 45) {
            riskScoreBar.style.backgroundColor = "#eab308";
        } else {
            riskScoreBar.style.backgroundColor = "#10b981";
        }

        // 4. Incident Summary
        summaryText.textContent = analysis.incident_summary || "No summary available.";

        // 5. Why this incident may be dangerous
        dangerText.textContent = analysis.why_dangerous || "Potential security compromise risk.";

        // 6. Possible attack vectors
        attackVectorsList.replaceChildren();
        const vectors = analysis.possible_attack_vectors || [];
        if (vectors.length === 0) {
            const li = document.createElement("li");
            li.textContent = "Unspecified external vector";
            attackVectorsList.appendChild(li);
        } else {
            vectors.forEach(function (vec) {
                const li = document.createElement("li");
                li.textContent = vec;
                attackVectorsList.appendChild(li);
            });
        }

        // 7. Potential impact
        potentialImpactList.replaceChildren();
        const impacts = analysis.potential_impact || [];
        if (impacts.length === 0) {
            const li = document.createElement("li");
            li.textContent = "Operational disruption or credential exposure";
            potentialImpactList.appendChild(li);
        } else {
            impacts.forEach(function (imp) {
                const li = document.createElement("li");
                li.textContent = imp;
                potentialImpactList.appendChild(li);
            });
        }

        // 8. Immediate Recommended Actions (Interactive Checklist)
        immediateActionsChecklist.replaceChildren();
        const actions = analysis.immediate_actions || [];
        actions.forEach(function (act, idx) {
            const item = document.createElement("label");
            item.className = "checklist-item";

            const checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.id = `action_check_${idx}`;

            const checkmark = document.createElement("span");
            checkmark.className = "checkbox-custom";

            const labelText = document.createElement("span");
            labelText.className = "checklist-label";
            labelText.textContent = act;

            checkbox.addEventListener("change", function () {
                if (checkbox.checked) {
                    item.classList.add("completed");
                } else {
                    item.classList.remove("completed");
                }
            });

            item.appendChild(checkbox);
            item.appendChild(checkmark);
            item.appendChild(labelText);
            immediateActionsChecklist.appendChild(item);
        });

        // 9. Long-Term Prevention Measures
        preventionList.replaceChildren();
        const preventions = analysis.prevention_measures || [];
        preventions.forEach(function (prev) {
            const li = document.createElement("li");
            li.textContent = prev;
            preventionList.appendChild(li);
        });

        // 10. Security Recommendations
        recommendationsList.replaceChildren();
        const recs = analysis.security_recommendations || [];
        recs.forEach(function (rec) {
            const li = document.createElement("li");
            li.textContent = rec;
            recommendationsList.appendChild(li);
        });

        // Show results dashboard & scroll smoothly
        resultsSection.style.display = "block";
        resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    // ----------------------------------------------------
    // Form Submission & Incident Analysis
    // ----------------------------------------------------
    form.addEventListener("submit", async function (event) {
        event.preventDefault();
        clearMessage();

        const description = descriptionInput.value.trim();
        const source = sourceInput.value.trim();

        // Validation
        if (!description) {
            showMessage("Please describe the cybersecurity issue or suspicious activity you are experiencing.", true);
            descriptionInput.focus();
            return;
        }

        if (description.length < 10) {
            showMessage("Description is too brief. Please enter at least 10 characters detailing the event.", true);
            descriptionInput.focus();
            return;
        }

        if (description.length > 3000) {
            showMessage("Description exceeds maximum allowed length (3000 characters). Please provide a concise summary.", true);
            descriptionInput.focus();
            return;
        }

        // Show loading state
        analyzeBtn.disabled = true;
        loadingIndicator.style.display = "flex";
        loadingIndicator.scrollIntoView({ behavior: "smooth", block: "center" });

        try {
            const response = await fetch(API_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    description: description,
                    source: source || "Not specified"
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || "Failed to analyze incident.");
            }

            // Render detailed intelligence results
            renderAnalysisResult(result);
            showMessage(`Incident classified as '${result.incident_type}' with severity '${result.severity}'. Saved to audit log!`);

            // Refresh table and telemetry
            await loadIncidents();
        } catch (error) {
            console.error("Submission error:", error);
            showMessage(error.message, true);
        } finally {
            analyzeBtn.disabled = false;
            loadingIndicator.style.display = "none";
        }
    });

    // "Analyze Another Incident" button
    analyzeAnotherBtn.addEventListener("click", function () {
        descriptionInput.value = "";
        sourceInput.value = "";
        updateCharCounter();
        clearMessage();
        form.scrollIntoView({ behavior: "smooth", block: "center" });
        descriptionInput.focus();
    });

    // "Download Full Report" button
    downloadReportBtn.addEventListener("click", function () {
        if (!currentIncidentId) {
            showMessage("No active incident report to download.", true);
            return;
        }
        window.location.href = `/api/incidents/${currentIncidentId}/report`;
    });

    // ----------------------------------------------------
    // Incident History Table & Filter Management
    // ----------------------------------------------------
    function renderIncidents() {
        tableBody.replaceChildren();

        const searchText = (searchInput.value || "").trim().toLowerCase();
        const selectedRisk = riskFilter.value;
        const selectedStatus = statusFilter.value;

        const filtered = incidents.filter(function (item) {
            const searchField = [
                item.type,
                item.description,
                item.source,
                item.severity,
                String(item.id)
            ].join(" ").toLowerCase();

            const matchesSearch = !searchText || searchField.includes(searchText);
            const matchesRisk = selectedRisk === "All" || item.severity === selectedRisk;
            const matchesStatus = selectedStatus === "All" || item.status === selectedStatus;

            return matchesSearch && matchesRisk && matchesStatus;
        });

        if (filtered.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 9;
            cell.style.textAlign = "center";
            cell.style.padding = "24px";
            cell.style.color = "#94a3b8";
            cell.textContent = incidents.length === 0
                ? (loading ? "Loading incident audit log..." : "No incidents recorded yet.")
                : "No matching incidents found for the selected filters.";
            row.appendChild(cell);
            tableBody.appendChild(row);
            return;
        }

        filtered.forEach(function (item) {
            const row = document.createElement("tr");

            // ID
            const idCell = document.createElement("td");
            idCell.textContent = `#${item.id}`;
            idCell.style.fontWeight = "bold";
            idCell.style.color = "#38bdf8";
            row.appendChild(idCell);

            // Category
            const typeCell = document.createElement("td");
            typeCell.textContent = item.type || "Other";
            typeCell.style.fontWeight = "600";
            row.appendChild(typeCell);

            // Description (truncated with full title)
            const descCell = document.createElement("td");
            descCell.className = "desc-cell";
            const shortDesc = item.description.length > 70
                ? item.description.substring(0, 67) + "..."
                : item.description;
            descCell.textContent = shortDesc;
            descCell.title = item.description;
            row.appendChild(descCell);

            // Source
            const sourceCell = document.createElement("td");
            sourceCell.textContent = item.source || "-";
            row.appendChild(sourceCell);

            // Severity
            const sevCell = document.createElement("td");
            const sevPill = document.createElement("span");
            sevPill.className = `table-pill ${getSeverityClass(item.severity)}`;
            sevPill.textContent = item.severity;
            sevCell.appendChild(sevPill);
            row.appendChild(sevCell);

            // Risk Score
            const riskCell = document.createElement("td");
            riskCell.textContent = `${item.riskScore}/100`;
            riskCell.style.fontWeight = "600";
            row.appendChild(riskCell);

            // Status
            const statusCell = document.createElement("td");
            const statusPill = document.createElement("span");
            statusPill.className = item.status === "Resolved" ? "status-pill resolved" : "status-pill open";
            statusPill.textContent = item.status;
            statusCell.appendChild(statusPill);
            row.appendChild(statusCell);

            // Date
            const dateCell = document.createElement("td");
            dateCell.textContent = item.date || "-";
            dateCell.style.whiteSpace = "nowrap";
            row.appendChild(dateCell);

            // Actions
            const actionCell = document.createElement("td");
            actionCell.className = "table-actions";

            // View Report button
            const viewBtn = document.createElement("button");
            viewBtn.type = "button";
            viewBtn.className = "tbl-btn view-btn";
            viewBtn.textContent = "View";
            viewBtn.title = "View complete 10-point intelligence report";
            viewBtn.addEventListener("click", function () {
                openReportModal(item);
            });
            actionCell.appendChild(viewBtn);

            // Resolve button (if Open)
            if (item.status !== "Resolved") {
                const resolveBtn = document.createElement("button");
                resolveBtn.type = "button";
                resolveBtn.className = "tbl-btn resolve-btn";
                resolveBtn.textContent = "Resolve";
                resolveBtn.title = "Mark this incident as Resolved";

                resolveBtn.addEventListener("click", async function () {
                    resolveBtn.disabled = true;
                    try {
                        const response = await fetch(`${API_URL}/${item.id}/resolve`, {
                            method: "PATCH"
                        });
                        const resData = await response.json();
                        if (!response.ok) throw new Error(resData.error || "Could not resolve incident.");
                        await loadIncidents();
                        showMessage(`Incident #${item.id} marked as Resolved.`);
                    } catch (err) {
                        console.error(err);
                        showMessage(err.message, true);
                    } finally {
                        resolveBtn.disabled = false;
                    }
                });
                actionCell.appendChild(resolveBtn);
            }

            // Delete button
            const deleteBtn = document.createElement("button");
            deleteBtn.type = "button";
            deleteBtn.className = "tbl-btn delete-btn";
            deleteBtn.textContent = "Delete";
            deleteBtn.title = "Delete this incident record";

            deleteBtn.addEventListener("click", async function () {
                if (!window.confirm(`Are you sure you want to delete Incident #${item.id}?`)) return;
                deleteBtn.disabled = true;
                try {
                    const response = await fetch(`${API_URL}/${item.id}`, {
                        method: "DELETE"
                    });
                    const resData = await response.json();
                    if (!response.ok) throw new Error(resData.error || "Could not delete incident.");
                    await loadIncidents();
                    showMessage(`Incident #${item.id} deleted successfully.`);
                } catch (err) {
                    console.error(err);
                    showMessage(err.message, true);
                } finally {
                    deleteBtn.disabled = false;
                }
            });
            actionCell.appendChild(deleteBtn);

            row.appendChild(actionCell);
            tableBody.appendChild(row);
        });
    }

    // ----------------------------------------------------
    // Modal Report Details
    // ----------------------------------------------------
    function openReportModal(incident) {
        modalCurrentId = incident.id;
        modalTitle.textContent = `Incident Report: #${incident.id} - ${incident.type}`;

        const analysis = incident.analysis || {};
        const vectors = (analysis.possible_attack_vectors || []).map(v => `<li>${v}</li>`).join("");
        const impacts = (analysis.potential_impact || []).map(i => `<li>${i}</li>`).join("");
        const actions = (analysis.immediate_actions || []).map(a => `<li>${a}</li>`).join("");
        const prevents = (analysis.prevention_measures || []).map(p => `<li>${p}</li>`).join("");
        const recs = (analysis.security_recommendations || []).map(r => `<li>${r}</li>`).join("");

        modalBody.innerHTML = `
            <div class="modal-meta-grid">
                <div><strong>Category:</strong> ${incident.type}</div>
                <div><strong>Severity:</strong> <span class="table-pill ${getSeverityClass(incident.severity)}">${incident.severity}</span></div>
                <div><strong>Risk Score:</strong> ${incident.riskScore} / 100</div>
                <div><strong>Status:</strong> ${incident.status}</div>
                <div><strong>Reported:</strong> ${incident.date}</div>
                <div><strong>Source / Device:</strong> ${incident.source || 'Not specified'}</div>
            </div>

            <div class="modal-section">
                <h4>Original Description:</h4>
                <p class="modal-box">${escapeHtml(incident.description)}</p>
            </div>

            <div class="modal-section">
                <h4>Incident Summary:</h4>
                <p class="modal-box">${escapeHtml(analysis.incident_summary || "Summary not generated.")}</p>
            </div>

            <div class="modal-section">
                <h4>Why Dangerous:</h4>
                <p class="modal-box">${escapeHtml(analysis.why_dangerous || "Security compromise hazard.")}</p>
            </div>

            <div class="modal-section">
                <h4>Attack Vectors:</h4>
                <ul class="cyber-list">${vectors || "<li>Unspecified vector</li>"}</ul>
            </div>

            <div class="modal-section">
                <h4>Potential Impact:</h4>
                <ul class="cyber-list">${impacts || "<li>Potential disruption</li>"}</ul>
            </div>

            <div class="modal-section">
                <h4>Immediate Recommended Actions:</h4>
                <ul class="cyber-list">${actions || "<li>Review credentials and isolate device.</li>"}</ul>
            </div>

            <div class="modal-section">
                <h4>Long-Term Prevention & Recommendations:</h4>
                <ul class="cyber-list">${prevents || recs || "<li>Enable MFA and adopt secure passwords.</li>"}</ul>
            </div>

            <div class="modal-disclaimer">
                ⚠️ <strong>Notice:</strong> This report is based on user-described incident context and cannot independently verify live system state.
            </div>
        `;

        reportModal.style.display = "flex";
    }

    function closeReportModal() {
        reportModal.style.display = "none";
        modalCurrentId = null;
    }

    closeModalBtn.addEventListener("click", closeReportModal);
    modalCloseActionBtn.addEventListener("click", closeReportModal);
    reportModal.addEventListener("click", function (e) {
        if (e.target === reportModal) closeReportModal();
    });

    modalDownloadBtn.addEventListener("click", function () {
        if (modalCurrentId) {
            window.location.href = `/api/incidents/${modalCurrentId}/report`;
        }
    });

    function escapeHtml(str) {
        if (!str) return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Filter event listeners
    searchInput.addEventListener("input", renderIncidents);
    riskFilter.addEventListener("change", renderIncidents);
    statusFilter.addEventListener("change", renderIncidents);

    // Initial load
    loadIncidents();
});
