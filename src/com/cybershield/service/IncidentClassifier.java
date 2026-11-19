package com.cybershield.service;

import com.cybershield.model.ThreatCategory;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Intelligent Natural Language Processing (NLP) Semantic Classifier.
 * Analyzes unstructured, non-technical incident descriptions and classifies them
 * into one of the 12 standardized cybersecurity categories without manual selection.
 */
public class IncidentClassifier {

    private final Map<ThreatCategory, List<String>> keywordDictionary;

    public IncidentClassifier() {
        this.keywordDictionary = new EnumMap<>(ThreatCategory.class);
        initKeywords();
    }

    private void initKeywords() {
        keywordDictionary.put(ThreatCategory.RANSOMWARE_ATTACK, Arrays.asList(
            "ransomware", "encrypted", "decrypt", "ransom note", "ransom", "bitcoin",
            "files locked", "extensions changed", "inaccessible", "locked files", "cannot open files"
        ));

        keywordDictionary.put(ThreatCategory.DATA_BREACH, Arrays.asList(
            "data breach", "database leaked", "leak", "leaked", "dumped", "pastebin",
            "records exposed", "customer data stolen", "confidential files", "haveibeenpwned"
        ));

        keywordDictionary.put(ThreatCategory.UNAUTHORIZED_ACCOUNT_ACCESS, Arrays.asList(
            "logged into my", "logged in without my permission", "account takeover",
            "account hacked", "someone is using my account", "someone accessed my",
            "profile taken over", "kicked out of my account", "unauthorized session"
        ));

        keywordDictionary.put(ThreatCategory.PASSWORD_COMPROMISE, Arrays.asList(
            "entered my password", "typed my password", "shared password", "password exposed",
            "stole my password", "gave them my password", "submitted credentials"
        ));

        keywordDictionary.put(ThreatCategory.PHISHING_ATTACK, Arrays.asList(
            "suspicious email", "phishing", "fake link", "unknown link", "clicked a link",
            "verify my bank", "verify account", "urgently update", "fake website", "impersonating"
        ));

        keywordDictionary.put(ThreatCategory.IDENTITY_THEFT, Arrays.asList(
            "identity theft", "identity stolen", "someone impersonating me", "ssn",
            "credit card opened", "loan in my name", "national id stolen", "forge my signature"
        ));

        keywordDictionary.put(ThreatCategory.SOCIAL_ENGINEERING, Arrays.asList(
            "call from tech support", "pretending to be support", "pretending to be microsoft",
            "fake support", "social engineering", "manipulated into", "gift card", "anydesk", "teamviewer"
        ));

        keywordDictionary.put(ThreatCategory.MALWARE_INFECTION, Arrays.asList(
            "pop-up", "popups", "running slowly", "malware", "virus", "trojan", "spyware",
            "adware", "unknown software installed", "antivirus alert", "browser hijacked"
        ));

        keywordDictionary.put(ThreatCategory.NETWORK_INTRUSION, Arrays.asList(
            "network intrusion", "ddos", "router hacked", "unauthorized ip", "port scan",
            "ports", "rogue device on wifi", "wifi hacked", "firewall alert", "scanning open ports"
        ));

        keywordDictionary.put(ThreatCategory.SUSPICIOUS_LOGIN, Arrays.asList(
            "suspicious login", "trying to access", "multiple failed logins", "repeatedly trying",
            "login attempt", "login alert", "unknown location", "unusual login", "new sign in"
        ));

        keywordDictionary.put(ThreatCategory.SUSPICIOUS_ACTIVITY, Arrays.asList(
            "suspicious activity", "strange behavior", "weird activity", "unusual traffic",
            "unexpected prompt", "strange notifications", "anomalous"
        ));
    }

    /**
     * Classifies plain text description into the best matching ThreatCategory.
     */
    public ThreatCategory classify(String rawText) {
        if (rawText == null || rawText.trim().length() < 5) {
            return ThreatCategory.OTHER;
        }

        String text = rawText.toLowerCase();
        Map<ThreatCategory, Double> scores = new EnumMap<>(ThreatCategory.class);
        for (ThreatCategory cat : ThreatCategory.values()) {
            scores.put(cat, 0.0);
        }

        // Weighted token matching
        for (Map.Entry<ThreatCategory, List<String>> entry : keywordDictionary.entrySet()) {
            ThreatCategory cat = entry.getKey();
            for (String kw : entry.getValue()) {
                if (text.contains(kw)) {
                    double weight = Pattern.compile("\\b" + Pattern.quote(kw) + "\\b").matcher(text).find() ? 2.5 : 1.2;
                    scores.put(cat, scores.get(cat) + weight);
                }
            }
        }

        // Contextual disambiguation rules
        if (text.contains("without my permission") || text.contains("logged into my") || text.contains("hacked my")) {
            scores.put(ThreatCategory.UNAUTHORIZED_ACCOUNT_ACCESS, scores.get(ThreatCategory.UNAUTHORIZED_ACCOUNT_ACCESS) + 4.0);
        }

        if (text.contains("repeatedly") || text.contains("trying to access") || text.contains("failed login")) {
            scores.put(ThreatCategory.SUSPICIOUS_LOGIN, scores.get(ThreatCategory.SUSPICIOUS_LOGIN) + 3.5);
        }

        if (text.contains("clicked") && (text.contains("link") || text.contains("password"))) {
            if (text.contains("password")) {
                scores.put(ThreatCategory.PASSWORD_COMPROMISE, scores.get(ThreatCategory.PASSWORD_COMPROMISE) + 3.5);
            } else {
                scores.put(ThreatCategory.PHISHING_ATTACK, scores.get(ThreatCategory.PHISHING_ATTACK) + 3.0);
            }
        }

        if (text.contains("extension") || text.contains("encrypted") || text.contains("inaccessible")) {
            scores.put(ThreatCategory.RANSOMWARE_ATTACK, scores.get(ThreatCategory.RANSOMWARE_ATTACK) + 5.0);
        }

        if (text.contains("pop-up") || text.contains("popups") || (text.contains("slowly") && text.contains("laptop"))) {
            scores.put(ThreatCategory.MALWARE_INFECTION, scores.get(ThreatCategory.MALWARE_INFECTION) + 4.0);
        }

        if (text.contains("port scan") || (text.contains("router") && (text.contains("wifi") || text.contains("device")))) {
            scores.put(ThreatCategory.NETWORK_INTRUSION, scores.get(ThreatCategory.NETWORK_INTRUSION) + 4.0);
        }

        ThreatCategory bestCat = ThreatCategory.OTHER;
        double maxScore = 0.5;

        for (Map.Entry<ThreatCategory, Double> entry : scores.entrySet()) {
            if (entry.getValue() > maxScore) {
                maxScore = entry.getValue();
                bestCat = entry.getKey();
            }
        }

        return bestCat;
    }

    /**
     * Extracts named entities such as platforms and devices.
     */
    public Map<String, String> extractEntities(String rawText) {
        String text = rawText.toLowerCase();
        Map<String, String> entities = new HashMap<>();

        if (text.contains("instagram")) entities.put("Platform", "Instagram");
        else if (text.contains("facebook")) entities.put("Platform", "Facebook");
        else if (text.contains("google") || text.contains("gmail")) entities.put("Platform", "Google / Gmail");
        else if (text.contains("bank") || text.contains("paypal")) entities.put("Platform", "Banking / Payment Portal");
        else if (text.contains("twitter") || text.contains("x.com")) entities.put("Platform", "Twitter / X");

        if (text.contains("laptop") || text.contains("pc") || text.contains("computer")) entities.put("Device", "Laptop / PC");
        else if (text.contains("phone") || text.contains("mobile") || text.contains("android") || text.contains("iphone")) entities.put("Device", "Smartphone");
        else if (text.contains("router") || text.contains("wifi")) entities.put("Device", "Network Router / Gateway");

        return entities;
    }
}
