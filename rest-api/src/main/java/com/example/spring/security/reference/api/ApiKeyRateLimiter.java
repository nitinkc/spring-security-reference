package com.example.spring.security.reference.api;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class ApiKeyRateLimiter {

    private final ConcurrentHashMap<String, Deque<Instant>> requests = new ConcurrentHashMap<>();

    public boolean allow(String key, int quota, long windowSeconds) {
        Instant now = Instant.now();
        Duration window = Duration.ofSeconds(windowSeconds);
        Deque<Instant> windowRequests = requests.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (windowRequests) {
            while (!windowRequests.isEmpty() && windowRequests.peekFirst().isBefore(now.minus(window))) {
                windowRequests.pollFirst();
            }
            if (windowRequests.size() >= quota) {
                return false;
            }
            windowRequests.addLast(now);
            return true;
        }
    }

    void reset() {
        requests.clear();
    }
}
