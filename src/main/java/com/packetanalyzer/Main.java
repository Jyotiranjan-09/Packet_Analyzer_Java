package com.packetanalyzer;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class Main {

    public static void main(String[] args) {
        System.out.println("==================================================");
        System.out.println("  Packet Analyzer & Multithreaded DPI Engine (Java)");
        System.out.println("==================================================\n");

        RuleManager ruleManager = new RuleManager();
        ruleManager.addRule(new RuleManager.Rule("Block Malicious Keyword", "TCP", "malware", null, "DROP"));
        ruleManager.addRule(new RuleManager.Rule("Alert HTTP GET", "TCP", "GET /", 80, "ALERT"));

        DpiEngine dpiEngine = new DpiEngine(ruleManager);
        ConnectionTracker connectionTracker = new ConnectionTracker(60000);
        FastPath fastPath = new FastPath();

        int workerCount = Runtime.getRuntime().availableProcessors();
        LoadBalancer loadBalancer = new LoadBalancer(workerCount);

        System.out.println("Initialized System with " + workerCount + " Worker Threads.\n");

        ExecutorService executor = Executors.newFixedThreadPool(workerCount);
        for (int i = 0; i < workerCount; i++) {
            final int workerId = i;
            executor.submit(() -> {
                ThreadSafeQueue<Packet> queue = loadBalancer.getWorkerQueue(workerId);
                try {
                    while (!Thread.currentThread().isInterrupted()) {
                        Packet packet = queue.poll(100, TimeUnit.MILLISECONDS);
                        if (packet == null) continue;

                        String cachedAction = fastPath.checkFastPath(packet);
                        if (cachedAction == null) {
                            DpiEngine.DpiResult result = dpiEngine.inspect(packet);
                            Connection conn = connectionTracker.trackPacket(packet);
                            conn.setDetectedProtocol(result.getDetectedProtocol());
                            if (result.getSniOrHost() != null) {
                                conn.setSni(result.getSniOrHost());
                            }

                            fastPath.cacheFlowAction(packet, result.getAction());
                            System.out.printf("[Worker-%d] [DPI-INSPECT] %s => %s%n",
                                    workerId, packet.getFiveTupleKey(), result);
                        } else {
                            System.out.printf("[Worker-%d] [FAST-PATH] %s => %s%n",
                                    workerId, packet.getFiveTupleKey(), cachedAction);
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }

        Packet[] samplePackets = new Packet[] {
            new Packet(1.0, "192.168.1.10", "142.250.190.46", 52344, 443, "TCP",
                    createTlsClientHelloPayload("example.com")),
            new Packet(1.1, "192.168.1.10", "93.184.216.34", 52345, 80, "TCP",
                    "GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n".getBytes()),
            new Packet(1.2, "192.168.1.15", "10.0.0.1", 60123, 80, "TCP",
                    "GET /download/malware.exe HTTP/1.1\r\nHost: badsite.com\r\n\r\n".getBytes()),
            new Packet(1.3, "192.168.1.10", "142.250.190.46", 52344, 443, "TCP",
                    "TLS Application Data payload".getBytes())
        };

        try {
            System.out.println("--> Injecting Synthetic Packets...");
            for (Packet packet : samplePackets) {
                loadBalancer.dispatch(packet);
                Thread.sleep(50);
            }

            Thread.sleep(500);
            executor.shutdownNow();

            System.out.println("\n==================================================");
            System.out.println("  Connection Tracker Summary");
            System.out.println("==================================================");
            for (Connection conn : connectionTracker.getActiveConnections()) {
                System.out.println(" - " + conn);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] createTlsClientHelloPayload(String sniHost) {
        byte[] hostBytes = sniHost.getBytes();
        byte[] payload = new byte[61 + hostBytes.length];
        payload[0] = 0x16;
        payload[1] = 0x03; payload[2] = 0x01;
        payload[5] = 0x01;

        int pos = 43;
        payload[pos++] = 0x00;
        payload[pos++] = 0x00; payload[pos++] = 0x02;
        pos += 2;
        payload[pos++] = 0x01; payload[pos++] = 0x00;

        int extLen = 9 + hostBytes.length;
        payload[pos++] = (byte)(extLen >> 8); payload[pos++] = (byte)(extLen & 0xFF);
        payload[pos++] = 0x00; payload[pos++] = 0x00;

        int sniExtLen = 5 + hostBytes.length;
        payload[pos++] = (byte)(sniExtLen >> 8); payload[pos++] = (byte)(sniExtLen & 0xFF);
        payload[pos++] = (byte)((sniExtLen - 2) >> 8); payload[pos++] = (byte)((sniExtLen - 2) & 0xFF);
        payload[pos++] = 0x00;
        payload[pos++] = (byte)(hostBytes.length >> 8); payload[pos++] = (byte)(hostBytes.length & 0xFF);

        System.arraycopy(hostBytes, 0, payload, pos, hostBytes.length);
        return payload;
    }
}
