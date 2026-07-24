package com.packetanalyzer;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.Collection;

public class ConnectionTracker {
    private final Map<String, Connection> activeConnections = new ConcurrentHashMap<>();
    private final long timeoutMs;

    public ConnectionTracker(long timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    public Connection trackPacket(Packet packet) {
        String key = packet.getSymmetricKey();
        Connection conn = activeConnections.computeIfAbsent(key, k -> new Connection(k));
        conn.update(packet);
        return conn;
    }

    public void cleanupTimedOutConnections() {
        long now = System.currentTimeMillis();
        activeConnections.entrySet().removeIf(entry -> {
            boolean timedOut = (now - entry.getValue().getLastSeenMs()) > timeoutMs;
            if (timedOut) {
                entry.getValue().setStatus("EXPIRED");
            }
            return timedOut;
        });
    }

    public Collection<Connection> getActiveConnections() {
        return activeConnections.values();
    }

    public int getActiveCount() {
        return activeConnections.size();
    }
}
