package com.packetanalyzer;

import java.util.concurrent.atomic.AtomicLong;

public class Connection {
    private String key;
    private long startTimeMs;
    private long lastSeenMs;
    private AtomicLong packetCount = new AtomicLong(0);
    private AtomicLong byteCount = new AtomicLong(0);
    private String detectedProtocol = "UNKNOWN";
    private String sni = null;
    private String status = "ACTIVE";

    public Connection(String key) {
        this.key = key;
        this.startTimeMs = System.currentTimeMillis();
        this.lastSeenMs = this.startTimeMs;
    }

    public synchronized void update(Packet packet) {
        this.lastSeenMs = System.currentTimeMillis();
        this.packetCount.incrementAndGet();
        this.byteCount.addAndGet(packet.getPayload().length);
    }

    public String getKey() { return key; }
    public long getStartTimeMs() { return startTimeMs; }
    public long getLastSeenMs() { return lastSeenMs; }
    public long getPacketCount() { return packetCount.get(); }
    public long getByteCount() { return byteCount.get(); }

    public String getDetectedProtocol() { return detectedProtocol; }
    public void setDetectedProtocol(String detectedProtocol) { this.detectedProtocol = detectedProtocol; }

    public String getSni() { return sni; }
    public void setSni(String sni) { this.sni = sni; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    @Override
    public String toString() {
        return String.format("ConnKey: %s | Packets: %d | Bytes: %d | AppProto: %s | SNI: %s | Status: %s",
                key, packetCount.get(), byteCount.get(), detectedProtocol, sni != null ? sni : "N/A", status);
    }
}
