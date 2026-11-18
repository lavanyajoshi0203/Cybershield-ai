import werkzeug
if not hasattr(werkzeug, "__version__"):
    import importlib.metadata
    try:
        werkzeug.__version__ = importlib.metadata.version("werkzeug")
    except Exception:
        werkzeug.__version__ = "3.1.3"

from flask import Flask, jsonify, request, send_from_directory, Response
import sqlite3
import json
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# Load local environment variables
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

from analyzer import generate_intelligent_analysis, CATEGORIES, DISCLAIMER_TEXT

app = Flask(__name__)
DB_PATH = BASE_DIR / "incidents.db"


def init_db():
    """Initialize database and migrate schema if newer columns are absent."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_type TEXT NOT NULL,
                description TEXT NOT NULL,
                source TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                created_at TEXT NOT NULL
            )
        """)

        # Backward-compatible column migration
        cursor = conn.execute("PRAGMA table_info(incidents)")
        columns = [row[1] for row in cursor.fetchall()]

        if "severity" not in columns:
            conn.execute("ALTER TABLE incidents ADD COLUMN severity TEXT DEFAULT 'Medium'")
        if "risk_score" not in columns:
            conn.execute("ALTER TABLE incidents ADD COLUMN risk_score INTEGER DEFAULT 50")
        if "analysis_json" not in columns:
            conn.execute("ALTER TABLE incidents ADD COLUMN analysis_json TEXT")


@app.route("/")
def home():
    """Serve the security analyst login page."""
    return send_from_directory(str(BASE_DIR), "login.html")


@app.route("/<path:filename>")
def frontend_files(filename):
    """Serve allowed static frontend assets."""
    allowed_files = {
        "login.html",
        "index.html",
        "style.css",
        "script.js"
    }

    if filename not in allowed_files:
        return jsonify({"error": "File not found"}), 404

    return send_from_directory(str(BASE_DIR), filename)


@app.route("/api/categories", methods=["GET"])
def get_categories():
    """Return the 12 supported incident categories."""
    return jsonify({
        "categories": CATEGORIES,
        "disclaimer": DISCLAIMER_TEXT
    })


@app.route("/api/incidents", methods=["GET"])
def get_incidents():
    """Fetch all recorded incidents sorted by newest first."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY id DESC"
        ).fetchall()

    incidents = []
    for row in rows:
        item = dict(row)
        analysis_data = None
        if item.get("analysis_json"):
            try:
                analysis_data = json.loads(item["analysis_json"])
            except Exception:
                analysis_data = None
        item["analysis"] = analysis_data
        incidents.append(item)

    return jsonify(incidents)


@app.route("/api/incidents/<int:incident_id>", methods=["GET"])
def get_incident_detail(incident_id):
    """Retrieve full detail for a single incident."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()

    if not row:
        return jsonify({"error": "Incident not found"}), 404

    item = dict(row)
    if item.get("analysis_json"):
        try:
            item["analysis"] = json.loads(item["analysis_json"])
        except Exception:
            item["analysis"] = None

    return jsonify(item)


@app.route("/api/incidents", methods=["POST"])
def add_incident():
    """
    Analyze and record a cybersecurity incident from a natural-language description.
    Automatically classifies the category and generates a 10-point threat intelligence report.
    """
    data = request.get_json(silent=True) or {}

    raw_description = data.get("description", "")
    if not isinstance(raw_description, str):
        return jsonify({"error": "Description must be a valid text string."}), 400

    description = raw_description.strip()
    source = str(data.get("source", "")).strip() or "Not specified"

    # Input validation
    if not description:
        return jsonify({"error": "Please describe the cybersecurity incident or issue you are experiencing."}), 400

    if len(description) < 10:
        return jsonify({
            "error": "Incident description is too brief. Please enter at least 10 characters with details about the issue."
        }), 400

    if len(description) > 3000:
        return jsonify({
            "error": "Incident description exceeds maximum allowed length (3000 characters). Please provide a concise summary."
        }), 400

    # Perform intelligent AI analysis
    try:
        analysis = generate_intelligent_analysis(description, source=source)
    except Exception as e:
        return jsonify({"error": f"Failed to analyze incident: {str(e)}"}), 500

    incident_type = analysis["incident_category"]
    severity = analysis["threat_severity"]
    risk_score = analysis["risk_score"]
    risk_level = severity  # Retain backward compatibility
    analysis_json_str = json.dumps(analysis)

    created_at = datetime.now().astimezone().isoformat(timespec="seconds")

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("""
            INSERT INTO incidents (
                incident_type,
                description,
                source,
                risk_level,
                severity,
                risk_score,
                status,
                created_at,
                analysis_json
            )
            VALUES (?, ?, ?, ?, ?, ?, 'Open', ?, ?)
        """, (
            incident_type,
            description,
            source,
            risk_level,
            severity,
            risk_score,
            created_at,
            analysis_json_str
        ))
        incident_id = cursor.lastrowid

    return jsonify({
        "message": "Incident classified and analyzed successfully",
        "id": incident_id,
        "incident_type": incident_type,
        "risk_level": risk_level,
        "severity": severity,
        "risk_score": risk_score,
        "analysis": analysis
    }), 201


@app.route("/api/incidents/<int:incident_id>/report", methods=["GET"])
def download_incident_report(incident_id):
    """Generate and return a downloadable cybersecurity incident report."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()

    if not row:
        return jsonify({"error": "Incident not found"}), 404

    item = dict(row)
    analysis = {}
    if item.get("analysis_json"):
        try:
            analysis = json.loads(item["analysis_json"])
        except Exception:
            analysis = {}

    report_lines = [
        "=" * 70,
        "CYBERSHIELD AI - CYBERSECURITY INCIDENT INTELLIGENCE REPORT",
        "=" * 70,
        f"Report ID:          INC-{item['id']:05d}",
        f"Generated At:       {item['created_at']}",
        f"Incident Category:  {item['incident_type']}",
        f"Threat Severity:    {item.get('severity', item['risk_level'])}",
        f"Risk Score:         {item.get('risk_score', 'N/A')}/100",
        f"Incident Status:    {item['status']}",
        f"Reported Source:    {item['source']}",
        "-" * 70,
        "1. INCIDENT DESCRIPTION (USER-REPORTED):",
        f"   {item['description']}",
        "",
        "2. INCIDENT SUMMARY:",
        f"   {analysis.get('incident_summary', 'N/A')}",
        "",
        "3. WHY THIS INCIDENT MAY BE DANGEROUS:",
        f"   {analysis.get('why_dangerous', 'N/A')}",
        "",
        "4. POSSIBLE ATTACK VECTORS:",
    ]

    for vec in analysis.get("possible_attack_vectors", []):
        report_lines.append(f"   • {vec}")

    report_lines.extend([
        "",
        "5. POTENTIAL IMPACT:",
    ])
    for imp in analysis.get("potential_impact", []):
        report_lines.append(f"   • {imp}")

    report_lines.extend([
        "",
        "6. IMMEDIATE RECOMMENDED ACTIONS (ACTION CHECKLIST):",
    ])
    for act in analysis.get("immediate_actions", []):
        report_lines.append(f"   [ ] {act}")

    report_lines.extend([
        "",
        "7. LONG-TERM PREVENTION MEASURES:",
    ])
    for prev in analysis.get("prevention_measures", []):
        report_lines.append(f"   • {prev}")

    report_lines.extend([
        "",
        "8. SECURITY RECOMMENDATIONS:",
    ])
    for rec in analysis.get("security_recommendations", []):
        report_lines.append(f"   • {rec}")

    report_lines.extend([
        "",
        "-" * 70,
        "SYSTEM DISCLAIMER & VERIFICATION NOTICE:",
        f"{analysis.get('disclaimer', DISCLAIMER_TEXT)}",
        "=" * 70,
    ])

    report_text = "\n".join(report_lines)
    filename = f"cybershield_incident_{item['id']}.txt"

    return Response(
        report_text,
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/api/incidents/<int:incident_id>/resolve", methods=["PATCH"])
def resolve_incident(incident_id):
    """Mark an incident as Resolved."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE incidents SET status = 'Resolved' WHERE id = ?",
            (incident_id,)
        )

    if cursor.rowcount == 0:
        return jsonify({"error": "Incident not found"}), 404

    return jsonify({"message": "Incident resolved successfully"})


@app.route("/api/incidents/<int:incident_id>", methods=["DELETE"])
def delete_incident(incident_id):
    """Delete an incident record."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "DELETE FROM incidents WHERE id = ?",
            (incident_id,)
        )

    if cursor.rowcount == 0:
        return jsonify({"error": "Incident not found"}), 404

    return jsonify({"message": "Incident deleted successfully"})


# Initialize the database on startup
init_db()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
