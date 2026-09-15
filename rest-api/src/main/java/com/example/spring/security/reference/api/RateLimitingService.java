package com.example.spring.security.reference.api;

import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimitingService {

    private static final int CAPACITY = 5;
    private static final long REFILL_INTERVAL_MILLIS = 1_000L;

    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public boolean tryAcquire(String key) {
        Bucket bucket = buckets.computeIfAbsent(key, Bucket::new);
        return bucket.tryAcquire();
    }

    public long getRetryAfterSeconds(String key) {
        Bucket bucket = buckets.get(key);
        if (bucket == null) {
            return 0;
        }
        return bucket.getRetryAfterSeconds();
    }

    private static class Bucket {

        private final Object lock = new Object();
        private int tokens;
        private long lastRefill;

        Bucket(String key) {
            this.tokens = CAPACITY;
            this.lastRefill = System.currentTimeMillis();
        }

        boolean tryAcquire() {
            long now = System.currentTimeMillis();
            synchronized (lock) {
                long elapsed = now - lastRefill;
                if (elapsed >= REFILL_INTERVAL_MILLIS) {
                    tokens = Math.min(CAPACITY, tokens + 1);
                    lastRefill = now;
                }

                if (tokens > 0) {
                    tokens--;
                    return true;
                }

                return false;
            }
        }

        long getRetryAfterSeconds() {
            synchronized (lock) {
                long elapsed = System.currentTimeMillis() - lastRefill;
                long remaining = REFILL_INTERVAL_MILLIS - elapsed;
                if (remaining <= 0) {
                    return 1;
                }
                return Math.max(1, (remaining + 999) / 1_000);
            }
        }
    }
}
