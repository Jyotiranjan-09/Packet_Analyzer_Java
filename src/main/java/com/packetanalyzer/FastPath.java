package com.packetanalyzer;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

public class FastPath {
    private final Map<String, String> flowCache = new ConcurrentHashMap<>();

    public String checkFastPath(Packet packet) {
        return flowCache.get(packet.getFiveTupleKey());
    }

    public void cacheFlowAction(Packet packet, String action) {
        flowCache.put(packet.getFiveTupleKey(), action);
    }

    public void invalidateFlow(Packet packet) {
        flowCache.remove(packet.getFiveTupleKey());
    }

    public void clear() {
        flowCache.clear();
    }

    public int size() {
        return flowCache.size();
    }
}
