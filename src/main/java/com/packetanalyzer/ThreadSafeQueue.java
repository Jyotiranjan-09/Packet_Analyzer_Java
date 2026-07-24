package com.packetanalyzer;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class ThreadSafeQueue<T> {
    private final LinkedBlockingQueue<T> queue;

    public ThreadSafeQueue() {
        this.queue = new LinkedBlockingQueue<>();
    }

    public ThreadSafeQueue(int capacity) {
        this.queue = new LinkedBlockingQueue<>(capacity);
    }

    public void enqueue(T item) throws InterruptedException {
        queue.put(item);
    }

    public T dequeue() throws InterruptedException {
        return queue.take();
    }

    public T poll(long timeout, TimeUnit unit) throws InterruptedException {
        return queue.poll(timeout, unit);
    }

    public int size() {
        return queue.size();
    }

    public boolean isEmpty() {
        return queue.isEmpty();
    }
}
