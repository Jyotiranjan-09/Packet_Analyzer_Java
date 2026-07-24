package com.packetanalyzer;

import java.nio.charset.StandardCharsets;

public class DpiEngine {

    public static class DpiResult {
        private String detectedProtocol;
        private String sniOrHost;
        private String matchedRule;
        private String action;

        public DpiResult(String detectedProtocol, String sniOrHost, String matchedRule, String action) {
            this.detectedProtocol = detectedProtocol;
            this.sniOrHost = sniOrHost;
            this.matchedRule = matchedRule;
            this.action = action;
        }

        public String getDetectedProtocol() { return detectedProtocol; }
        public String getSniOrHost() { return sniOrHost; }
        public String getMatchedRule() { return matchedRule; }
        public String getAction() { return action; }

        @Override
        public String toString() {
            return String.format("Proto: %s | SNI/Host: %s | Rule: %s | Action: %s",
                    detectedProtocol, sniOrHost != null ? sniOrHost : "None",
                    matchedRule != null ? matchedRule : "None", action);
        }
    }

    private final RuleManager ruleManager;

    public DpiEngine(RuleManager ruleManager) {
        this.ruleManager = ruleManager;
    }

    public DpiResult inspect(Packet packet) {
        String protocol = identifyProtocol(packet);
        String sni = SniExtractor.extractSni(packet);

        RuleManager.Rule matchedRule = ruleManager.evaluate(packet);
        String ruleName = matchedRule != null ? matchedRule.getName() : null;
        String action = matchedRule != null ? matchedRule.getAction() : "ALLOW";

        return new DpiResult(protocol, sni, ruleName, action);
    }

    private String identifyProtocol(Packet packet) {
        int dstPort = packet.getDstPort();
        int srcPort = packet.getSrcPort();
        byte[] payload = packet.getPayload();

        if (dstPort == 80 || srcPort == 80) {
            return "HTTP";
        } else if (dstPort == 443 || srcPort == 443) {
            return "HTTPS/TLS";
        } else if (dstPort == 53 || srcPort == 53) {
            return "DNS";
        } else if (dstPort == 22 || srcPort == 22) {
            return "SSH";
        } else if (dstPort == 21 || srcPort == 21) {
            return "FTP";
        }

        if (payload != null && payload.length > 0) {
            String str = new String(payload, StandardCharsets.ISO_8859_1);
            if (str.startsWith("GET ") || str.startsWith("POST ") || str.startsWith("HTTP/")) {
                return "HTTP";
            }
            if (payload[0] == 0x16) {
                return "HTTPS/TLS";
            }
        }

        return packet.getProtocol();
    }
}
