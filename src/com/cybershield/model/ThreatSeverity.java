package com.cybershield.model;

import java.awt.Color;

/**
 * Enumeration of threat severity levels with corresponding color codes and threshold boundaries.
 */
public enum ThreatSeverity {
    CRITICAL("Critical", new Color(239, 68, 68), 85),
    HIGH("High", new Color(249, 115, 22), 70),
    MEDIUM("Medium", new Color(234, 179, 8), 45),
    LOW("Low", new Color(16, 185, 129), 0);

    private final String displayName;
    private final Color badgeColor;
    private final int minScoreThreshold;

    ThreatSeverity(String displayName, Color badgeColor, int minScoreThreshold) {
        this.displayName = displayName;
        this.badgeColor = badgeColor;
        this.minScoreThreshold = minScoreThreshold;
    }

    public String getDisplayName() {
        return displayName;
    }

    public Color getBadgeColor() {
        return badgeColor;
    }

    public int getMinScoreThreshold() {
        return minScoreThreshold;
    }

    public static ThreatSeverity fromScore(int score) {
        if (score >= CRITICAL.minScoreThreshold) return CRITICAL;
        if (score >= HIGH.minScoreThreshold) return HIGH;
        if (score >= MEDIUM.minScoreThreshold) return MEDIUM;
        return LOW;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
