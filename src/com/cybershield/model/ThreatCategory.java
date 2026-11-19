package com.cybershield.model;

/**
 * Enumeration of the 12 standardized cybersecurity incident categories.
 * Aligned with NIST SP 800-61 and MITRE ATT&CK taxonomies.
 */
public enum ThreatCategory {
    SUSPICIOUS_LOGIN("Suspicious Login", "Anomalous or repeated unauthorized login attempts.", 65),
    UNAUTHORIZED_ACCOUNT_ACCESS("Unauthorized Account Access", "Active account takeover or session breach.", 82),
    PHISHING_ATTACK("Phishing Attack", "Deceptive communication designed to harvest credentials or data.", 75),
    MALWARE_INFECTION("Malware Infection", "Presence of malicious software degrading system operation.", 68),
    RANSOMWARE_ATTACK("Ransomware Attack", "Extortion-driven file encryption or denial of access.", 92),
    PASSWORD_COMPROMISE("Password Compromise", "Exposure or unauthorized submission of account credentials.", 80),
    IDENTITY_THEFT("Identity Theft", "Misuse of personal identity, documents, or credit information.", 87),
    SOCIAL_ENGINEERING("Social Engineering", "Human psychological manipulation to bypass security.", 74),
    DATA_BREACH("Data Breach", "Unauthorized exposure or exfiltration of sensitive records.", 88),
    NETWORK_INTRUSION("Network Intrusion", "Unauthorized perimeter penetration or network anomaly.", 78),
    SUSPICIOUS_ACTIVITY("Suspicious Activity", "Anomalous system, device, or account behavior.", 55),
    OTHER("Other / Unclassified", "Unclassified security event requiring manual audit.", 40);

    private final String displayName;
    private final String description;
    private final int baseRiskScore;

    ThreatCategory(String displayName, String description, int baseRiskScore) {
        this.displayName = displayName;
        this.description = description;
        this.baseRiskScore = baseRiskScore;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    public int getBaseRiskScore() {
        return baseRiskScore;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
