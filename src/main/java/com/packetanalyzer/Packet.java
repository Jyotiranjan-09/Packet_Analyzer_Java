package com.packetanalyzer;

public class Packet {
    private double timestamp;
    private String srcIp;
    private String dstIp;
    private int srcPort;
    private int dstPort;
    private String protocol; // "TCP", "UDP", etc.
    private byte[] payload;

    public Packet(double timestamp, String srcIp, String dstIp, int srcPort, int dstPort, String protocol, byte[] payload) {
        this.timestamp = timestamp;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
        this.payload = payload != null ? payload : new byte[0];
    }

    public double getTimestamp() { return timestamp; }
    public String getSrcIp() { return srcIp; }
    public String getDstIp() { return dstIp; }
    public int getSrcPort() { return srcPort; }
    public int getDstPort() { return dstPort; }
    public String getProtocol() { return protocol; }
    public byte[] getPayload() { return payload; }

    public String getFiveTupleKey() {
        return srcIp + ":" + srcPort + "->" + dstIp + ":" + dstPort + " [" + protocol + "]";
    }

    public String getSymmetricKey() {
        if (srcIp.compareTo(dstIp) < 0 || (srcIp.equals(dstIp) && srcPort <= dstPort)) {
            return srcIp + ":" + srcPort + "<->" + dstIp + ":" + dstPort + " [" + protocol + "]";
        } else {
            return dstIp + ":" + dstPort + "<->" + srcIp + ":" + srcPort + " [" + protocol + "]";
        }
    }

    @Override
    public String toString() {
        return String.format("[%s] %s:%d -> %s:%d (Payload len: %d)",
                protocol, srcIp, srcPort, dstIp, dstPort, payload.length);
    }
}
