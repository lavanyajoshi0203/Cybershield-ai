package com.cybershield;

import com.cybershield.controller.IncidentController;
import com.cybershield.view.CyberShieldMainFrame;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/**
 * Main Application Entry Point for CyberShield AI (Java Edition).
 * Initializes Controller, Services, and opens the main Desktop Dashboard GUI.
 */
public class Main {

    public static void main(String[] args) {
        // Set System Look & Feel
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {}

        SwingUtilities.invokeLater(() -> {
            IncidentController controller = new IncidentController();

            // Pre-seed a sample demonstration record for immediate review
            try {
                controller.processIncident(
                    "Someone logged into my Instagram account without my permission from an unfamiliar IP address.",
                    "Instagram App"
                );
            } catch (Exception ignored) {}

            CyberShieldMainFrame frame = new CyberShieldMainFrame(controller);
            frame.setVisible(true);
        });
    }
}
