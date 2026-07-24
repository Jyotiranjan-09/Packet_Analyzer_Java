package com.packetanalyzer;

import java.util.ArrayList;
import java.util.List;

public class LoadBalancer {
    private final List<ThreadSafeQueue<Packet>> workerQueues;
    private final int workerCount;

    public LoadBalancer(int workerCount) {
        this.workerCount = workerCount;
        this.workerQueues = new ArrayList<>(workerCount);
        for (int i = 0; i < workerCount; i++) {
            workerQueues.add(new ThreadSafeQueue<>(10000));
        }
    }

    public void dispatch(Packet packet) throws InterruptedException {
        int workerIndex = Math.abs(packet.getSymmetricKey().hashCode()) % workerCount;
        workerQueues.get(workerIndex).enqueue(packet);
    }

    public ThreadSafeQueue<Packet> getWorkerQueue(int index) {
        return workerQueues.get(index);
    }

    public int getWorkerCount() {
        return workerCount;
    }
}
