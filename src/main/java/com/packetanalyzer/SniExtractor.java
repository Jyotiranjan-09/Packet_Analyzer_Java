package com.packetanalyzer;

import java.nio.charset.StandardCharsets;

public class SniExtractor {

    public static String extractSni(Packet packet) {
        byte[] payload = packet.getPayload();
        if (payload == null || payload.length == 0) return null;

        String httpHost = extractHttpHost(payload);
        if (httpHost != null) return httpHost;

        return extractTlsSni(payload);
    }

    private static String extractHttpHost(byte[] payload) {
        try {
            String data = new String(payload, StandardCharsets.UTF_8);
            if (data.startsWith("GET ") || data.startsWith("POST ") || data.startsWith("HEAD ") ||
                data.startsWith("PUT ") || data.startsWith("DELETE ") || data.startsWith("CONNECT ")) {
                
                String[] lines = data.split("\r?\n");
                for (String line : lines) {
                    if (line.toLowerCase().startsWith("host:")) {
                        return line.substring(5).trim();
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static String extractTlsSni(byte[] payload) {
        if (payload.length < 43) return null;
        if (payload[0] != 0x16) return null;

        int pos = 5;
        if (payload[pos] != 0x01) return null;

        pos += 4;
        pos += 2;
        pos += 32;

        if (pos >= payload.length) return null;

        int sessionIdLen = payload[pos] & 0xFF;
        pos += 1 + sessionIdLen;

        if (pos + 2 > payload.length) return null;

        int cipherSuitesLen = ((payload[pos] & 0xFF) << 8) | (payload[pos + 1] & 0xFF);
        pos += 2 + cipherSuitesLen;

        if (pos >= payload.length) return null;

        int compMethodsLen = payload[pos] & 0xFF;
        pos += 1 + compMethodsLen;

        if (pos + 2 > payload.length) return null;

        int extensionsLen = ((payload[pos] & 0xFF) << 8) | (payload[pos + 1] & 0xFF);
        pos += 2;

        int extensionsEnd = pos + extensionsLen;
        while (pos + 4 <= extensionsEnd && pos + 4 <= payload.length) {
            int extType = ((payload[pos] & 0xFF) << 8) | (payload[pos + 1] & 0xFF);
            int extLen = ((payload[pos + 2] & 0xFF) << 8) | (payload[pos + 3] & 0xFF);
            pos += 4;

            if (extType == 0x0000) {
                if (pos + 5 <= payload.length) {
                    int serverNameListLen = ((payload[pos] & 0xFF) << 8) | (payload[pos + 1] & 0xFF);
                    int nameType = payload[pos + 2] & 0xFF;
                    if (nameType == 0) {
                        int nameLen = ((payload[pos + 3] & 0xFF) << 8) | (payload[pos + 4] & 0xFF);
                        if (pos + 5 + nameLen <= payload.length) {
                            return new String(payload, pos + 5, nameLen, StandardCharsets.UTF_8);
                        }
                    }
                }
            }
            pos += extLen;
        }

        return null;
    }
}
