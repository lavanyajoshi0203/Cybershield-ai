# 🛡️ CyberShield AI
### AI-Powered Cyber Incident Detection & Analysis System

CyberShield AI is an intelligent cybersecurity incident detection and triage platform. Users describe cybersecurity issues or suspicious activity in plain, natural language without requiring any technical cybersecurity knowledge. The system automatically classifies the incident across 12 threat categories, calculates a dynamic risk score (0–100), and generates a comprehensive 10-point actionable intelligence report.

---

## 📌 Features

- **Natural Language Incident Intake:** Describe issues in plain text with no mandatory category dropdowns.
- **One-Click Example Prompts:** Preloaded realistic cyber scenarios (Instagram takeover, banking phishing, ransomware files, leaked passwords, slow laptop with pop-ups, repeated logins).
- **Automated AI Incident Classification:** Classifies incidents into 12 supported cybersecurity categories using an intelligent NLP engine.
- **Dynamic 10-Point Intelligence Report:**
  1. Detected Incident Category
  2. Threat Severity: Critical, High, Medium, or Low
  3. Dynamic Risk Score (0–100) with visual bar indicator
  4. Incident Summary
  5. Why This Incident May Be Dangerous
  6. Possible Attack Vectors
  7. Potential Impact
  8. Immediate Recommended Actions (interactive, checkable mitigation checklist)
  9. Long-Term Prevention Measures
  10. Security Recommendations
- **Downloadable Incident Reports:** Download full incident intelligence summaries in formatted text (`.txt`).
- **Telemetry & Severity Analytics:** Real-time visual progress bars displaying distribution of Critical, High, Medium, and Low severity events.
- **Audit Log & History Management:** Search, filter by severity or resolution status, inspect full historical reports in modals, resolve, or delete incidents.
- **Preserved Analyst Portal:** Clean authentication landing page (`login.html`) leading directly to the dashboard.
- **Clear System Disclaimer:** Explicitly notifies users that the system assesses reported descriptions for triage guidance and does not independently scan external live devices or networks.

---

## 🏷️ Supported Incident Categories

1. **Suspicious Login**
2. **Unauthorized Account Access**
3. **Phishing Attack**
4. **Malware Infection**
5. **Ransomware Attack**
6. **Password Compromise**
7. **Identity Theft**
8. **Social Engineering**
9. **Data Breach**
10. **Network Intrusion**
11. **Suspicious Activity**
12. **Other / Unclassified**

---

## 🧰 Technologies Used

- **Frontend:** HTML5, CSS3 (Modern Cyber Theme with Cyan & Blue accents), Vanilla JavaScript
- **Backend:** Python 3, Flask REST API
- **AI / NLP Engine:** `analyzer.py` (Domain-specific heuristic & semantic classification engine, contextual entity extraction, optional LLM integration via `.env`)
- **Database:** SQLite (`incidents.db` with automated backward-compatible schema migrations)

---

## ⚙️ Installation and Setup

### 1. Clone the repository
```bash
git clone https://github.com/lavanyajoshi0203/Cybershield-ai.git
cd Cybershield-ai
```

### 2. Install dependencies
```bash
python -m pip install -r requirements.txt
```

### 3. (Optional) Configure Environment Variables
Copy `.env.example` to `.env` to configure optional external LLM providers or custom ports:
```bash
copy .env.example .env
```
*Note: If no API keys are provided in `.env`, the system runs 100% offline using its built-in NLP cybersecurity engine.*

### 4. Start the application
```bash
python app.py
```

### 5. Access the Dashboard
Open your web browser and navigate to:
```
http://127.0.0.1:5000/
```
Click **"Sign In to Dashboard →"** on the analyst portal to enter the incident analysis dashboard.

---

## ⚠️ Disclaimer

CyberShield AI analyzes user-submitted incident descriptions only and cannot independently verify whether an actual account, device, or network was compromised. The assessment and recommendations are generated for incident triage and security guidance.
