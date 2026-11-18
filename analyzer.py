"""
CyberShield AI - Intelligent Incident Classification and Reasoning Engine
Provides automated natural language classification across 12 cybersecurity categories
and dynamic 10-point threat analysis.
"""

import os
import re
import json
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables if .env exists
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# 12 Target Categories
CATEGORIES = [
    "Suspicious Login",
    "Unauthorized Account Access",
    "Phishing Attack",
    "Malware Infection",
    "Ransomware Attack",
    "Password Compromise",
    "Identity Theft",
    "Social Engineering",
    "Data Breach",
    "Network Intrusion",
    "Suspicious Activity",
    "Other / Unclassified"
]

DISCLAIMER_TEXT = (
    "This system analyzes the user's description only and cannot independently verify "
    "whether an actual account, device, or network was compromised. The assessment and "
    "recommendations are generated for incident triage and guidance purposes."
)

# Semantic keyword and pattern dictionaries for classification
INTENT_PATTERNS = {
    "Ransomware Attack": {
        "keywords": [
            "ransomware", "encrypted", "decrypt", "ransom note", "ransom", "bitcoins",
            "files locked", "extensions changed", "cannot open files", "inaccessible",
            ".locked", ".crypto", "pay to recover", "files are held", "cryptor", "lockbit"
        ],
        "weight": 2.5,
        "default_severity": "Critical",
        "base_score": 92
    },
    "Data Breach": {
        "keywords": [
            "data breach", "database leaked", "leak", "leaked", "dumped", "pastebin",
            "records exposed", "customer data stolen", "confidential files", "exfiltrated",
            "haveibeenpwned", "breached", "source code leak", "pii exposed"
        ],
        "weight": 2.2,
        "default_severity": "Critical",
        "base_score": 88
    },
    "Unauthorized Account Access": {
        "keywords": [
            "logged into my", "logged in without my permission", "account takeover",
            "account hacked", "hacked my account", "someone is using my account",
            "someone accessed my", "profile taken over", "kicked out of my account",
            "password was changed by someone", "intruder in my account", "unauthorized session",
            "unauthorized access to my"
        ],
        "weight": 2.1,
        "default_severity": "High",
        "base_score": 82
    },
    "Password Compromise": {
        "keywords": [
            "entered my password", "typed my password", "shared password", "password exposed",
            "password leak", "credential stuffing", "stole my password", "password reset",
            "gave them my password", "revealed credentials", "submitted login credentials"
        ],
        "weight": 2.0,
        "default_severity": "High",
        "base_score": 80
    },
    "Phishing Attack": {
        "keywords": [
            "suspicious email", "phishing", "fake link", "unknown link", "clicked a link",
            "verify my bank", "verify account", "urgently update", "fake website",
            "impersonating", "scam link", "sms link", "smishing", "email asking me to",
            "fraudulent email", "bogus website", "spoofed email"
        ],
        "weight": 1.9,
        "default_severity": "High",
        "base_score": 75
    },
    "Identity Theft": {
        "keywords": [
            "identity theft", "identity stolen", "someone impersonating me", "ssn",
            "social security", "credit card opened", "loan in my name", "bank account opened",
            "national id stolen", "tax return filed", "forge my signature", "forged identity"
        ],
        "weight": 2.0,
        "default_severity": "Critical",
        "base_score": 87
    },
    "Social Engineering": {
        "keywords": [
            "call from tech support", "pretending to be support", "pretending to be microsoft",
            "fake support", "social engineering", "manipulated into", "coerced", "gift card",
            "money transfer scam", "ceo fraud", "whatsapp scam", "wire money", "remote desktop software",
            "anydesk", "teamviewer"
        ],
        "weight": 1.8,
        "default_severity": "High",
        "base_score": 74
    },
    "Malware Infection": {
        "keywords": [
            "pop-up", "popups", "running slowly", "malware", "virus", "trojan", "spyware",
            "adware", "unknown software installed", "antivirus alert", "miner", "high cpu",
            "browser hijacked", "redirecting to strange pages", "weird software", "infected"
        ],
        "weight": 1.8,
        "default_severity": "Medium",
        "base_score": 68
    },
    "Network Intrusion": {
        "keywords": [
            "network intrusion", "ddos", "dos attack", "router hacked", "unauthorized ip",
            "port scan", "dns spoofing", "man in the middle", "mitm", "rogue device on wifi",
            "wifi hacked", "firewall alert", "packet flood", "arp spoofing", "scanning open ports",
            "open ports", "unrecognized device connected to my wifi", "router", "wifi", "network traffic"
        ],
        "weight": 2.2,
        "default_severity": "High",
        "base_score": 78
    },
    "Suspicious Login": {
        "keywords": [
            "suspicious login", "trying to access", "multiple failed logins", "repeatedly trying",
            "login attempt", "login alert", "unknown location",
            "unusual login", "new sign in", "sign-in notification", "2fa prompt received"
        ],
        "weight": 1.7,
        "default_severity": "Medium",
        "base_score": 65
    },
    "Suspicious Activity": {
        "keywords": [
            "suspicious activity", "strange behavior", "weird activity", "unusual traffic",
            "unexpected prompt", "strange notifications", "anomalous", "unexplained"
        ],
        "weight": 1.2,
        "default_severity": "Medium",
        "base_score": 55
    }
}


def extract_entities(text: str) -> dict:
    """Extract context entities such as platforms, devices, and exposed elements."""
    text_lower = text.lower()
    
    platforms = []
    platform_map = {
        "Instagram": ["instagram", "ig"],
        "Facebook / Meta": ["facebook", "meta", "fb"],
        "WhatsApp": ["whatsapp"],
        "Google / Gmail": ["google", "gmail", "youtube", "google drive"],
        "Bank / Financial Portal": ["bank", "banking", "credit card", "debit card", "paypal", "wire transfer", "payment"],
        "Twitter / X": ["twitter", "x.com"],
        "Microsoft / Outlook": ["microsoft", "outlook", "office 365", "onedrive", "azure"],
        "Apple / iCloud": ["apple", "icloud", "iphone", "macbook"],
        "LinkedIn": ["linkedin"],
        "Crypto / Wallet": ["crypto", "cryptocurrency", "bitcoin", "binance", "metamask", "wallet"],
        "Corporate / Work Network": ["company", "vpn", "work email", "corporate", "internal server"]
    }
    for name, tokens in platform_map.items():
        if any(re.search(r"\b" + re.escape(t) + r"\b", text_lower) for t in tokens):
            platforms.append(name)

    devices = []
    device_map = {
        "Personal Computer / Laptop": ["laptop", "computer", "pc", "desktop", "mac", "windows"],
        "Smartphone / Mobile Device": ["phone", "mobile", "android", "iphone", "smartphone"],
        "Network Router / Gateway": ["router", "wifi", "modem", "gateway", "access point"],
        "Server / Cloud Host": ["server", "database", "cloud", "aws", "vps"]
    }
    for dev, tokens in device_map.items():
        if any(re.search(r"\b" + re.escape(t) + r"\b", text_lower) for t in tokens):
            devices.append(dev)

    has_financial = any(w in text_lower for w in ["bank", "money", "funds", "credit card", "card", "payment", "wire", "transfer", "dollars", "inr", "rupees"])
    has_credentials = any(w in text_lower for w in ["password", "credential", "pin", "otp", "2fa", "code", "secret"])
    has_ransom = any(w in text_lower for w in ["ransom", "bitcoin", "encrypted", "pay"])

    return {
        "platforms": platforms,
        "devices": devices,
        "has_financial": has_financial,
        "has_credentials": has_credentials,
        "has_ransom": has_ransom
    }


def classify_incident(text: str) -> tuple[str, float]:
    """
    Classify the natural language description into one of the 12 supported categories.
    Returns (category_name, confidence_score).
    """
    text_lower = text.lower()
    scores = {cat: 0.0 for cat in CATEGORIES}

    # Match predefined weighted patterns
    for category, config in INTENT_PATTERNS.items():
        weight = config["weight"]
        for kw in config["keywords"]:
            if kw in text_lower:
                # Give higher score if keyword matches as whole phrase/word
                if re.search(r"\b" + re.escape(kw) + r"\b", text_lower):
                    scores[category] += 2.0 * weight
                else:
                    scores[category] += 1.0 * weight

    # Specific contextual disambiguation heuristics
    # If unauthorized takeover happened vs just repeated attempts
    if "without my permission" in text_lower or "logged into" in text_lower or "hacked my" in text_lower:
        if "instagram" in text_lower or "facebook" in text_lower or "account" in text_lower:
            scores["Unauthorized Account Access"] += 4.0

    if "repeatedly" in text_lower or "trying to access" in text_lower or "failed login" in text_lower:
        scores["Suspicious Login"] += 3.5

    if "clicked" in text_lower and ("link" in text_lower or "entered" in text_lower or "password" in text_lower):
        if "password" in text_lower:
            scores["Password Compromise"] += 3.0
            scores["Phishing Attack"] += 2.5
        else:
            scores["Phishing Attack"] += 3.5

    if "port scan" in text_lower or "ports" in text_lower or ("router" in text_lower and ("device" in text_lower or "wifi" in text_lower)):
        scores["Network Intrusion"] += 4.5

    if "extension" in text_lower or "encrypted" in text_lower or "inaccessible" in text_lower:
        scores["Ransomware Attack"] += 5.0

    if "pop-up" in text_lower or "popups" in text_lower or ("slowly" in text_lower and "laptop" in text_lower):
        scores["Malware Infection"] += 4.0

    best_cat = max(scores, key=scores.get)
    max_score = scores[best_cat]

    if max_score < 1.0:
        return "Other / Unclassified", 0.35

    confidence = min(0.98, max(0.60, max_score / (max_score + 3.0)))
    return best_cat, confidence


def compute_risk_and_severity(category: str, text: str, entities: dict) -> tuple[str, int]:
    """
    Calculate dynamic risk score (0-100) and severity level based on category and contextual factors.
    """
    base_info = INTENT_PATTERNS.get(category, {"base_score": 50, "default_severity": "Medium"})
    score = base_info["base_score"]

    # Additive and subtractive modifiers
    if entities.get("has_financial"):
        score += 8
    if entities.get("has_credentials"):
        score += 7
    if entities.get("has_ransom"):
        score += 10

    # Length / detail complexity factor
    if len(text) > 150:
        score += 2

    # Clamping
    score = max(10, min(100, score))

    if score >= 85:
        severity = "Critical"
    elif score >= 70:
        severity = "High"
    elif score >= 45:
        severity = "Medium"
    else:
        severity = "Low"

    return severity, score


def generate_intelligent_analysis(text: str, source: str = "") -> dict:
    """
    Analyze incident description and produce complete 10-point dynamic intelligence report.
    """
    clean_text = text.strip()
    entities = extract_entities(clean_text)
    category, confidence = classify_incident(clean_text)
    severity, risk_score = compute_risk_and_severity(category, clean_text, entities)

    target_env = ", ".join(entities["platforms"]) if entities["platforms"] else (source if source else "User system/account")
    device_env = ", ".join(entities["devices"]) if entities["devices"] else "Endpoint device"

    # Context-specific Dynamic Content Generation
    if category == "Ransomware Attack":
        summary = f"Detected high-confidence Ransomware Attack activity affecting {device_env}. Files have reportedly become inaccessible with abnormal extension changes."
        danger_reason = "Ransomware rapidly encrypts local and connected network drives, permanently locking personal and sensitive data. Attackers often exfiltrate data for double-extortion."
        attack_vectors = [
            "Malicious email attachments (macros, malicious archives)",
            "Drive-by downloads from compromised websites",
            "Exposed Remote Desktop Protocol (RDP) or unpatched software vulnerabilities",
            "Tainted freeware or pirated software installers"
        ]
        impact = [
            "Total operational downtime and loss of vital documents/files",
            "Potential data exfiltration and public disclosure",
            "Financial extortion demands and recovery costs"
        ]
        immediate_actions = [
            "Immediately disconnect this computer from Wi-Fi, Ethernet, and all local networks to stop lateral spread.",
            "Disconnect and unplug all attached external hard drives, USBs, and cloud storage sync tools immediately.",
            "Do NOT pay the ransom demand, as payment does not guarantee file decryption and finances further criminal operations.",
            "Preserve sample encrypted files and photograph ransom notes for forensic analysis and police/CERT reporting.",
            "Check for clean, offline backups created prior to the first sign of disruption."
        ]
        prevention_measures = [
            "Maintain immutable, offline (air-gapped) or immutable cloud backups following the 3-2-1 backup rule.",
            "Keep operating systems, hypervisors, and security patches updated without delay.",
            "Implement Endpoint Detection and Response (EDR) software with behavioral ransomware protection."
        ]
        recommendations = [
            "Consult the 'No More Ransom' initiative (nomoreransom.org) to check if free decryption keys exist for your strain.",
            "Perform a clean OS reinstallation from verified media once forensics are collected.",
            "Audit all network endpoints and change all master credentials once systems are restored."
        ]

    elif category == "Unauthorized Account Access":
        summary = f"Detected Unauthorized Account Takeover on {target_env}. An unauthorized third party has gained access without user authorization."
        danger_reason = "An intruder controlling your account can read private messages, impersonate you to scam contacts, modify recovery settings, and pivot into linked accounts."
        attack_vectors = [
            "Credential stuffing or password spraying from prior data breaches",
            "Phishing lures capturing session tokens or login credentials",
            "Session hijacking or cookie theft via malware on personal devices",
            "Weak or reused passwords across online services"
        ]
        impact = [
            "Loss of control over personal profile, identity, and sensitive communications",
            "Reputational damage through malicious posts or messages sent to contacts",
            "Financial fraud if payment methods or digital assets are linked"
        ]
        immediate_actions = [
            f"Navigate immediately to {target_env} Security Settings and click 'Log out of all other sessions / devices'.",
            "Change your account password immediately to a strong, unique 16+ character passphrase.",
            "Enable Two-Factor Authentication (2FA) using an Authenticator App (Google Authenticator, Microsoft Authenticator) rather than SMS.",
            "Inspect and verify your account recovery email, phone number, and linked third-party apps for any unauthorized additions.",
            "Notify close contacts and friends if suspicious messages were dispatched from your handle."
        ]
        prevention_measures = [
            "Never reuse the same password across multiple platforms or email accounts.",
            "Use a reputable password manager to generate and store high-entropy unique passwords.",
            "Monitor sign-in alert emails and review active device lists on a regular monthly schedule."
        ]
        recommendations = [
            "Verify whether the associated primary email account is also compromised; secure it first.",
            "Download and safely store backup recovery codes in an encrypted or physical location.",
            "Check haveibeenpwned.com to see if your credentials were leaked in public data dumps."
        ]

    elif category == "Suspicious Login":
        summary = f"Detected repeated or anomalous login attempts directed against {target_env} from unfamiliar sources or unexpected geographical locations."
        danger_reason = "Persistent unauthorized login attempts indicate targeted brute force attacks, credential stuffing, or leaked credentials being tested by automated bots."
        attack_vectors = [
            "Automated botnet dictionary and brute-force attacks",
            "Credential stuffing attacks using stolen breach databases",
            "Targeted password guessing based on open-source intelligence (OSINT)"
        ]
        impact = [
            "Imminent account takeover if weak passwords or lack of multi-factor authentication exists",
            "Potential account lockouts due to excessive failed attempts triggered by attackers",
            "User alert fatigue leading to accidental approval of 2FA push notifications (MFA fatigue)"
        ]
        immediate_actions = [
            "Update your current account password to a strong, unique passphrase immediately.",
            "Ensure Multi-Factor Authentication (MFA / 2FA) is strictly enforced on the account.",
            "Review login history and security logs to determine IP addresses, device types, and locations involved.",
            "Never approve unexpected two-factor prompts or push notifications ('MFA fatigue').",
            "Confirm that secondary recovery emails and SMS numbers belong exclusively to you."
        ]
        prevention_measures = [
            "Adopt passkeys or FIDO2 hardware security keys where supported.",
            "Disable outdated authentication protocols or legacy IMAP/POP services if applicable.",
            "Set up geo-blocking or conditional access policies if using professional/enterprise accounts."
        ]
        recommendations = [
            "Enable push or email alerts for every new login from an unrecognized device.",
            "Do not disclose your username or email in public cybersecurity forums.",
            "Audit password strength across all associated services."
        ]

    elif category == "Phishing Attack":
        summary = f"Detected Phishing attack targeting {target_env}. Fraudulent communications or deceptive links were used to manipulate the user into revealing sensitive information."
        danger_reason = "Phishing websites convincingly mimic trusted financial institutions, social platforms, and services to steal account credentials, credit card details, and personal data."
        attack_vectors = [
            "Deceptive emails or SMS messages with spoofed sender headers or lookalike domains",
            "Urgency-inducing messages claiming account suspension, bank verification, or unpaid bills",
            "Malicious URLs redirecting through multiple intermediaries to evade spam filters"
        ]
        impact = [
            "Direct compromise of user passwords, PINs, or banking authorization credentials",
            "Secondary malware installation if the fraudulent site prompts downloads",
            "Identity theft and unauthorized monetary transactions"
        ]
        immediate_actions = [
            "Do NOT click any further links, enter credentials, or reply to the suspicious communication.",
            "If credentials were submitted, IMMEDIATELY navigate directly to the legitimate service and change your password.",
            "Contact your financial institution or bank immediately if payment information or bank logins were entered.",
            "Report the phishing email or link within your email client and to the Anti-Phishing Working Group (APWG).",
            "Scan your device with updated security software to ensure no background payload was installed."
        ]
        prevention_measures = [
            "Always inspect the domain name in the browser address bar before typing passwords.",
            "Never click verification or login links received via email or text; bookmark and access official URLs directly.",
            "Deploy email filtering solutions with SPF, DKIM, and DMARC verification mechanisms."
        ]
        recommendations = [
            "Utilize modern web browsers with built-in anti-phishing protection (e.g., Google Safe Browsing / Microsoft SmartScreen).",
            "Use hardware security keys (FIDO2) which are cryptographically immune to phishing attacks.",
            "Educate family members or team members regarding urgency-based social engineering."
        ]

    elif category == "Password Compromise":
        summary = f"Detected high-risk Password Compromise event involving {target_env}. Credentials were submitted to an untrusted destination or exposed."
        danger_reason = "Exposed passwords grant adversaries direct access to private services and enable credential stuffing attacks against every other service where the password was reused."
        attack_vectors = [
            "Entry of credentials on phishing pages or malicious forms",
            "Keystroke logging malware resident on an endpoint",
            "Credential scraping from unencrypted transmission channels (HTTP, public Wi-Fi)"
        ]
        impact = [
            "Immediate unauthorized access to the compromised account and services sharing the password",
            "Data exfiltration, unauthorized purchases, or blackmail",
            "Compromise of interconnected identity ecosystems (e.g., Single Sign-On)"
        ]
        immediate_actions = [
            "Immediately change the password for the compromised service from a verified clean device.",
            "Identify ALL other websites and accounts where you used the same or similar password, and change them right away.",
            "Terminate all existing active sessions on the affected services.",
            "Enable Two-Factor Authentication (2FA) across all accounts.",
            "Review recent account activity (orders, emails, sent messages, transaction logs) for unauthorized actions."
        ]
        prevention_measures = [
            "Never reuse passwords across multiple sites; each account must possess a unique password.",
            "Use an encrypted password manager (e.g., Bitwarden, 1Password) to generate 16+ character random passwords.",
            "Store emergency recovery keys in a safe, offline location."
        ]
        recommendations = [
            "Check haveibeenpwned.com to monitor ongoing exposure of your email addresses.",
            "Run a thorough malware scan to ensure no keylogger is active on the device used.",
            "Enable credit monitoring or bank transaction notifications if financial accounts are involved."
        ]

    elif category == "Malware Infection":
        summary = f"Detected signs of Malware Infection on {device_env}. Symptoms include pop-up alerts, performance degradation, and anomalous system behaviors."
        danger_reason = "Malware can harvest stored passwords, spy through webcams/microphones, log keystrokes, hijack web browsers, and enslave the machine into a botnet."
        attack_vectors = [
            "Execution of infected attachments or freeware downloads",
            "Exploitation of unpatched browser or operating system vulnerabilities",
            "Malicious browser extensions or rogue desktop notifications",
            "Infected USB drives or external storage peripherals"
        ]
        impact = [
            "Severe system instability, data theft, and unauthorized resource utilization (e.g., crypto mining)",
            "Interception of online banking transactions and personal credentials",
            "Pivoting into other devices connected to the same home or work local network"
        ]
        immediate_actions = [
            "Disconnect the device from the internet (unplug Ethernet, turn off Wi-Fi) to cut off communication with threat actors.",
            "Boot the system into Safe Mode and execute a full scan with a reputable antivirus solution (e.g., Windows Defender / Malwarebytes).",
            "Open Task Manager / Activity Monitor to inspect running processes and terminate suspicious unknown tasks.",
            "Audit and remove unfamiliar browser extensions and recently installed programs from Control Panel / Settings.",
            "Clear all browser cache, cookies, and website notification permissions."
        ]
        prevention_measures = [
            "Keep the OS, drivers, browsers, and antivirus software automatically updated.",
            "Avoid downloading pirated software, cracks, or media from peer-to-peer torrent networks.",
            "Operate on standard user privileges rather than administrative accounts for day-to-day web browsing."
        ]
        recommendations = [
            "If malware persists or system files are compromised, perform a clean OS reinstallation.",
            "Change all sensitive passwords from a different, known-clean device after the infection is contained.",
            "Enable real-time firewall and web protection."
        ]

    elif category == "Identity Theft":
        summary = f"Detected potential Identity Theft event involving personal credentials, financial details, or impersonation of {target_env}."
        danger_reason = "Stolen identities are leveraged to open fraudulent credit lines, file counterfeit tax refunds, drain financial accounts, or conduct illegal activities under the victim's name."
        attack_vectors = [
            "Large-scale commercial data breaches exposing PII (SSN, National ID, date of birth)",
            "Targeted spear-phishing or physical document interception (mail theft)",
            "Compromised government, healthcare, or financial databases"
        ]
        impact = [
            "Devastating impact on personal credit scores and credit standing",
            "Financial liability for unauthorized loans and credit card charges",
            "Protracted legal and bureaucratic challenges required to restore legal identity"
        ]
        immediate_actions = [
            "Contact major credit bureaus (Equifax, Experian, TransUnion) immediately and place a fraud alert / credit freeze on your credit report.",
            "Notify your bank and financial institutions of potential identity compromise to place security holds on accounts.",
            "File an official report with identitytheft.gov (or local national cybercrime authority) and your local police department.",
            "Audit all recent bank statements, tax filings, and credit inquiries for anomalies.",
            "Change passwords and security questions across all government, utility, and financial portals."
        ]
        prevention_measures = [
            "Keep credit reports frozen by default, lifting the freeze only when applying for legitimate credit.",
            "Shred physical documents containing sensitive information before disposal.",
            "Never provide identity numbers or card details over unsolicited phone calls or unverified websites."
        ]
        recommendations = [
            "Enroll in an accredited identity monitoring service to receive real-time credit inquiry alerts.",
            "Set up multi-factor authentication with an authenticator app across all financial portals.",
            "Maintain an organized incident log file of all communications with credit bureaus and authorities."
        ]

    elif category == "Social Engineering":
        summary = f"Detected Social Engineering attack against {target_env}. Psychological manipulation or fraudulent pretexts were deployed to trick the user into granting access or funds."
        danger_reason = "Social engineers exploit trust, fear, authority, or urgency to bypass technical defenses, frequently leading to remote access compromise or direct financial loss."
        attack_vectors = [
            "Fake technical support representatives claiming system infection and requesting remote access",
            "Impersonation of executive management, colleagues, or government agencies",
            "Urgent demands for wire transfers, gift cards, or cryptocurrency payments"
        ]
        impact = [
            "Installation of persistent remote access trojans (RATs) such as AnyDesk, TeamViewer, or ScreenConnect",
            "Irreversible loss of financial funds via gift cards or wire transfers",
            "Compromise of confidential company or personal records"
        ]
        immediate_actions = [
            "Immediately terminate all communication with the caller or sender; hang up the phone or disconnect chat.",
            "If remote access software (AnyDesk, TeamViewer) was installed, disconnect internet and uninstall the software completely.",
            "If money or gift card codes were dispatched, contact your bank or card issuer immediately to attempt transaction stoppage.",
            "Run an antivirus scan to ensure no secondary backdoors were introduced during the remote session.",
            "Change your primary computer login and account passwords."
        ]
        prevention_measures = [
            "Legitimate organizations (e.g. Microsoft, Google, banks) will NEVER make unsolicited calls requiring remote desktop access or gift card payments.",
            "Verify all out-of-band requests by hanging up and calling back on an independently verified public number.",
            "Educate family members on modern voice cloning and tech support scam techniques."
        ]
        recommendations = [
            "File a complaint with the FTC (reportfraud.ftc.gov) or local consumer protection bureau.",
            "Monitor financial accounts closely over the subsequent 30-90 days for unusual activity.",
            "Block the fraudster's telephone number and email address."
        ]

    elif category == "Data Breach":
        summary = f"Detected exposure linked to a Data Breach affecting {target_env}. Sensitive records, credentials, or personal information may have leaked into unauthorized hands."
        danger_reason = "Breached databases are traded on dark web marketplaces, enabling mass automated credential stuffing, identity fraud, and hyper-targeted spear phishing."
        attack_vectors = [
            "Compromised third-party cloud database or web application vulnerability (e.g., SQL injection, misconfigured S3 bucket)",
            "Insider threat or malicious data exfiltration from service provider",
            "Infostealer malware infections harvesting stored browser credentials"
        ]
        impact = [
            "Exposure of passwords, personal email, phone numbers, addresses, and payment data",
            "Vulnerability to account takeovers across any platforms sharing the same email or password",
            "Long-term exposure to targeted spam, phishing, and scam campaigns"
        ]
        immediate_actions = [
            "Change passwords immediately for the breached service and all services sharing the same credentials.",
            "Enable Multi-Factor Authentication on your primary email and related web accounts.",
            "Search your email address on haveibeenpwned.com to review which specific services and datasets were leaked.",
            "Beware of follow-up phishing emails referencing the breach designed to trick you into entering new passwords on fake sites.",
            "Audit financial statements for fraudulent activity if payment cards were associated with the breached company."
        ]
        prevention_measures = [
            "Use email aliases or relay services (e.g., SimpleLogin, Apple Hide My Email) when signing up for secondary sites.",
            "Never store plain text passwords or sensitive data in cloud documents or unencrypted notes.",
            "Adopt unique, high-entropy passwords generated exclusively by a password manager."
        ]
        recommendations = [
            "Subscribe to breach notification alerts (e.g. Have I Been Pwned alerts).",
            "Request deletion of inactive accounts and data under relevant privacy laws (GDPR/CCPA).",
            "Review connected third-party OAuth apps and revoke dormant authorizations."
        ]

    elif category == "Network Intrusion":
        summary = f"Detected potential Network Intrusion or perimeter anomaly targeting {target_env}. Unauthorized traffic or anomalous device activity identified."
        danger_reason = "Network intruders can intercept unencrypted data packets, execute man-in-the-middle attacks, compromise IoT devices, and gain persistent access to internal hosts."
        attack_vectors = [
            "Exploitation of default or weak Wi-Fi encryption (WPA/WEP) or default router admin credentials",
            "Open, unmonitored ports exposed to the public internet without firewall filtering",
            "Compromised IoT device (smart cameras, smart bulbs) functioning as a network foothold"
        ]
        impact = [
            "Eavesdropping on internal network traffic and sensitive communications",
            "Redirection of DNS queries to malicious phishing servers (DNS hijacking)",
            "Unauthorized access to local shared files, network storage (NAS), and printers"
        ]
        immediate_actions = [
            "Access your router administration page and review all connected devices; disconnect and block any unrecognized MAC/IP addresses.",
            "Immediately change the router administrator password and Wi-Fi WPA3/WPA2 security passphrase.",
            "Update router firmware to the newest manufacturer security release.",
            "Disable remote router administration and Universal Plug and Play (UPnP) in the router settings.",
            "Disconnect vulnerable or outdated IoT appliances from the primary network and move them to an isolated Guest network."
        ]
        prevention_measures = [
            "Separate sensitive computing devices from smart IoT devices using VLANs or separate guest SSIDs.",
            "Ensure all web traffic utilizes HTTPS and configure Encrypted DNS (DNS over HTTPS / DNS over TLS).",
            "Maintain active firewall rules and close unnecessary forwarded ports."
        ]
        recommendations = [
            "Run a network audit scan using trusted tools (e.g., Nmap) to detect unintended open listening ports.",
            "Use a reputable Virtual Private Network (VPN) when operating on public or shared Wi-Fi networks.",
            "Review router event logs periodically for unusual connection surges or brute force attempts."
        ]

    else:  # Suspicious Activity or Other / Unclassified
        summary = f"Detected anomalous Suspicious Activity in relation to {target_env}. The described behavior deviates from normal system operations."
        danger_reason = "Unresolved security anomalies can be initial indicators of stealthy reconnaissance, persistent background malware, or early stages of an account intrusion."
        attack_vectors = [
            "Unidentified background processes or scheduled tasks executing anomalous routines",
            "Potential social engineering or reconnaissance probing by external actors",
            "Misconfigured system permissions or unintended software installations"
        ]
        impact = [
            "Risk of escalating into full compromise if left uninvestigated",
            "Unintended exposure of private files or system resources",
            "System performance degradation and security alerts"
        ]
        immediate_actions = [
            "Carefully observe and document exact times, URLs, error messages, or device behaviors.",
            "Perform a comprehensive offline security scan of your operating system with updated antivirus definitions.",
            "Update passwords on primary communications and banking accounts as a precautionary defense.",
            "Check for unauthorized active sessions across your primary online profiles.",
            "Ensure operating system and installed software packages are up to date."
        ]
        prevention_measures = [
            "Establish regular backup routines for critical files and personal records.",
            "Enable Multi-Factor Authentication (2FA) wherever supported.",
            "Avoid installing applications from unverified sources or clicking unsolicited links."
        ]
        recommendations = [
            "If further anomalies occur, seek professional assistance or submit technical logs for deeper forensic review.",
            "Review recent browser history and software installation logs.",
            "Maintain vigilance against social engineering or follow-up phishing attempts."
        ]

    return {
        "incident_category": category,
        "threat_severity": severity,
        "risk_score": risk_score,
        "confidence": confidence,
        "incident_summary": summary,
        "why_dangerous": danger_reason,
        "possible_attack_vectors": attack_vectors,
        "potential_impact": impact,
        "immediate_actions": immediate_actions,
        "prevention_measures": prevention_measures,
        "security_recommendations": recommendations,
        "disclaimer": DISCLAIMER_TEXT,
        "analyzed_at": datetime.now().astimezone().isoformat(timespec="seconds")
    }
