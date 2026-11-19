package com.cybershield.service;

import com.cybershield.model.AnalysisReport;
import com.cybershield.model.ThreatCategory;
import com.cybershield.model.ThreatSeverity;

import java.util.Arrays;
import java.util.Map;

/**
 * Service responsible for computing dynamic risk scores (0-100),
 * determining threat severity, and synthesizing the 10-point intelligence report.
 */
public class RiskAssessmentService {

    public AnalysisReport generateReport(String description, String source, ThreatCategory category, Map<String, String> entities) {
        AnalysisReport report = new AnalysisReport();
        report.setCategory(category);

        // 1. Compute dynamic risk score (0-100)
        int score = computeRiskScore(category, description);
        report.setRiskScore(score);

        // 2. Derive Severity from score
        ThreatSeverity severity = ThreatSeverity.fromScore(score);
        report.setSeverity(severity);

        // 3. Dynamic target label
        String target = entities.getOrDefault("Platform", entities.getOrDefault("Device", source));
        if (target == null || target.isBlank() || target.equalsIgnoreCase("Not specified")) {
            target = "User Account / Endpoint";
        }

        // 4. Populate 10 Items dynamically based on Category & Context
        switch (category) {
            case RANSOMWARE_ATTACK:
                report.setSummary("High-confidence Ransomware activity detected on " + target + ". Files are reported inaccessible with abnormal extensions.");
                report.setWhyDangerous("Ransomware rapidly encrypts local and network storage, permanently destroying files or holding data hostage for financial extortion.");
                report.setAttackVectors(Arrays.asList(
                    "Malicious email attachments or macro scripts",
                    "Drive-by malicious downloads or tainted software",
                    "Compromised Remote Desktop Protocol (RDP) ports"
                ));
                report.setPotentialImpacts(Arrays.asList(
                    "Total operational downtime and loss of vital personal/work documents",
                    "Extortion demands and public disclosure of sensitive data",
                    "Lateral infection spreading across connected local network devices"
                ));
                report.setImmediateActions(Arrays.asList(
                    "Immediately disconnect computer from Wi-Fi, Ethernet, and local networks.",
                    "Unplug external backup drives, USB keys, and cloud sync services.",
                    "Do NOT pay ransom demands; check nomoreransom.org for decryption keys.",
                    "Preserve sample encrypted files and photograph ransom notes for forensics."
                ));
                report.setPreventionMeasures(Arrays.asList(
                    "Maintain isolated, air-gapped 3-2-1 offline backups.",
                    "Apply operating system security patches promptly."
                ));
                report.setRecommendations(Arrays.asList(
                    "Perform clean OS reinstallation from verified media.",
                    "Deploy modern endpoint protection with behavioral ransomware detection."
                ));
                break;

            case UNAUTHORIZED_ACCOUNT_ACCESS:
                report.setSummary("Unauthorized Account Takeover detected on " + target + ". An unauthorized third party gained access without user permission.");
                report.setWhyDangerous("Attackers with account access can exfiltrate private messages, impersonate the victim, lock recovery emails, and hijack linked accounts.");
                report.setAttackVectors(Arrays.asList(
                    "Credential stuffing from prior public breach databases",
                    "Phishing lures capturing session tokens or login details",
                    "Reused passwords across compromised online platforms"
                ));
                report.setPotentialImpacts(Arrays.asList(
                    "Total loss of control over personal profile, identity, and messages",
                    "Reputational damage through malicious messages sent to contacts",
                    "Financial fraud if payment methods or digital wallets are linked"
                ));
                report.setImmediateActions(Arrays.asList(
                    "Open " + target + " Security Settings and click 'Log out of all other sessions'.",
                    "Change your account password immediately to a strong 16+ character passphrase.",
                    "Enable Two-Factor Authentication (2FA) via an Authenticator App.",
                    "Verify account recovery phone number and email for unauthorized changes."
                ));
                report.setPreventionMeasures(Arrays.asList(
                    "Never reuse passwords across platforms; use a password manager.",
                    "Review active sessions and login alerts on a monthly basis."
                ));
                report.setRecommendations(Arrays.asList(
                    "Check haveibeenpwned.com to see where your credentials leaked.",
                    "Download and store account recovery codes in a secure offline location."
                ));
                break;

            case PHISHING_ATTACK:
                report.setSummary("Phishing attack detected targeting " + target + ". Deceptive messages or fake links were deployed to manipulate the user.");
                report.setWhyDangerous("Phishing websites mimic legitimate institutions to steal credentials, credit card details, and authorization tokens.");
                report.setAttackVectors(Arrays.asList(
                    "Deceptive emails or SMS messages with spoofed sender headers",
                    "Urgency-inducing messages claiming account suspension or bank verification",
                    "Lookalike domain names redirecting to fraudulent login forms"
                ));
                report.setPotentialImpacts(Arrays.asList(
                    "Direct theft of account passwords, PINs, or banking logins",
                    "Identity theft and unauthorized monetary fund transfers",
                    "Installation of spyware or infostealer malware"
                ));
                report.setImmediateActions(Arrays.asList(
                    "Do NOT click any further links, enter credentials, or reply to the sender.",
                    "If credentials were submitted, immediately change passwords on the official website.",
                    "Contact your financial institution immediately if card/bank logins were entered.",
                    "Mark the email as Phishing/Spam in your email client."
                ));
                report.setPreventionMeasures(Arrays.asList(
                    "Always verify the exact domain name in your browser address bar.",
                    "Never click login links in unsolicited emails; navigate directly via official URLs."
                ));
                report.setRecommendations(Arrays.asList(
                    "Use hardware security keys (FIDO2/WebAuthn) immune to phishing.",
                    "Report the fraudulent URL to the Anti-Phishing Working Group (APWG)."
                ));
                break;

            case PASSWORD_COMPROMISE:
                report.setSummary("Critical Password Compromise detected involving " + target + ". Credentials were typed into an untrusted link or exposed.");
                report.setWhyDangerous("An exposed password gives adversaries direct access and enables automated credential stuffing attacks against all other accounts sharing the password.");
                report.setAttackVectors(Arrays.asList(
                    "Credential entry on fraudulent phishing portals",
                    "Keystroke logging malware resident on an infected endpoint",
                    "Credential interception over unencrypted public Wi-Fi"
                ));
                report.setPotentialImpacts(Arrays.asList(
                    "Immediate unauthorized access across all services sharing the password",
                    "Data exfiltration, unauthorized online orders, or blackmail",
                    "Compromise of primary Single Sign-On (SSO) email identity"
                ));
                report.setImmediateActions(Arrays.asList(
                    "Immediately change password for the affected account from a clean device.",
                    "Identify and update ALL other accounts where the same password was reused.",
                    "Terminate all active login sessions on the affected platforms.",
                    "Enable Multi-Factor Authentication (2FA) immediately."
                ));
                report.setPreventionMeasures(Arrays.asList(
                    "Use a password manager (e.g. Bitwarden) to generate unique passwords.",
                    "Never write down or store plain text passwords in cloud notes."
                ));
                report.setRecommendations(Arrays.asList(
                    "Run an antivirus scan on the device used when the password was exposed.",
                    "Subscribe to breach alerts to monitor future exposure."
                ));
                break;

            case MALWARE_INFECTION:
                report.setSummary("Malware Infection indicators identified on " + target + ". Symptoms include pop-up alerts, high CPU usage, and system slowdowns.");
                report.setWhyDangerous("Malware can log keystrokes, steal browser cookies, spy through webcams, and enlist machines into botnets.");
                report.setAttackVectors(Arrays.asList(
                    "Downloaded files, pirated software, or tainted installers",
                    "Malicious browser extensions or rogue notification permissions",
                    "Exploitation of unpatched browser and system vulnerabilities"
                ));
                report.setPotentialImpacts(Arrays.asList(
                    "Theft of stored browser passwords, session cookies, and crypto keys",
                    "Severe operating system instability and loss of control",
                    "Unauthorized remote access trojans (RATs) established on system"
                ));
                report.setImmediateActions(Arrays.asList(
                    "Disconnect the device from the internet (turn off Wi-Fi/unplug Ethernet).",
                    "Boot into Safe Mode and run a full scan with Windows Defender / Malwarebytes.",
                    "Inspect Task Manager for unknown background processes.",
                    "Remove unrecognized browser extensions and recently downloaded software."
                ));
                report.setPreventionMeasures(Arrays.asList(
                    "Keep operating systems, browsers, and antivirus definitions updated.",
                    "Avoid downloading pirated software or cracks from torrents."
                ));
                report.setRecommendations(Arrays.asList(
                    "If malware persists, perform a clean operating system reinstallation.",
                    "Change sensitive passwords from a known-clean secondary device."
                ));
                break;

            default:
                report.setSummary("Suspicious activity detected regarding " + target + ". Anomalous events deviate from standard operating baselines.");
                report.setWhyDangerous("Unresolved anomalies can represent early reconnaissance probes or initial stages of a sophisticated intrusion.");
                report.setAttackVectors(Arrays.asList(
                    "Automated bot scanning or credential stuffing attempts",
                    "Unidentified background tasks or anomalous network traffic"
                ));
                report.setPotentialImpacts(Arrays.asList(
                    "Risk of escalating into complete compromise if left unaddressed",
                    "Unauthorized attempts to bypass authentication barriers"
                ));
                report.setImmediateActions(Arrays.asList(
                    "Update account passwords and ensure Multi-Factor Authentication is active.",
                    "Review recent login history and verify recognized devices.",
                    "Run a comprehensive anti-malware scan across the system."
                ));
                report.setPreventionMeasures(Arrays.asList(
                    "Adopt unique passphrases and maintain routine offline backups."
                ));
                report.setRecommendations(Arrays.asList(
                    "Document anomalous timestamps and contact platform support if issues persist."
                ));
                break;
        }

        return report;
    }

    private int computeRiskScore(ThreatCategory category, String description) {
        int score = category.getBaseRiskScore();
        String text = description.toLowerCase();

        if (text.contains("bank") || text.contains("money") || text.contains("card") || text.contains("funds")) {
            score += 8;
        }
        if (text.contains("password") || text.contains("credential") || text.contains("pin") || text.contains("otp")) {
            score += 7;
        }
        if (text.contains("ransom") || text.contains("encrypted") || text.contains("bitcoin")) {
            score += 10;
        }
        if (description.length() > 150) {
            score += 2;
        }

        return Math.max(10, Math.min(100, score));
    }
}
