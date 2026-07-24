package com.packetanalyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class RuleManager {

    public static class Rule {
        private String name;
        private String protocol;
        private Pattern payloadPattern;
        private Integer targetPort;
        private String action;

        public Rule(String name, String protocol, String regexPattern, Integer targetPort, String action) {
            this.name = name;
            this.protocol = protocol;
            this.payloadPattern = regexPattern != null ? Pattern.compile(regexPattern, Pattern.CASE_INSENSITIVE) : null;
            this.targetPort = targetPort;
            this.action = action;
        }

        public boolean matches(Packet packet) {
            if (protocol != null && !protocol.equalsIgnoreCase(packet.getProtocol())) {
                return false;
            }
            if (targetPort != null && packet.getDstPort() != targetPort && packet.getSrcPort() != targetPort) {
                return false;
            }
            if (payloadPattern != null) {
                String payloadStr = new String(packet.getPayload());
                return payloadPattern.matcher(payloadStr).find();
            }
            return true;
        }

        public String getName() { return name; }
        public String getAction() { return action; }
    }

    private final List<Rule> rules = new ArrayList<>();

    public void addRule(Rule rule) {
        rules.add(rule);
    }

    public Rule evaluate(Packet packet) {
        for (Rule rule : rules) {
            if (rule.matches(packet)) {
                return rule;
            }
        }
        return null;
    }
}
