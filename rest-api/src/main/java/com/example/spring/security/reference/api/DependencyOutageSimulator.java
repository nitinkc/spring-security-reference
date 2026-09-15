package com.example.spring.security.reference.api;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Simulates the health of a downstream identity dependency (for example, a
 * remote token introspection endpoint) so tests can exercise timeout and
 * outage handling without a real network dependency.
 *
 * A real deployment would observe latency and errors from an actual HTTP
 * client instead of a settable mode.
 */
@Component
public class DependencyOutageSimulator {

    public enum Mode {
        HEALTHY,
        SLOW,
        DOWN
    }

    private final AtomicReference<Mode> mode = new AtomicReference<>(Mode.HEALTHY);

    public void setMode(Mode newMode) {
        mode.set(newMode);
    }

    public Mode getMode() {
        return mode.get();
    }

    /**
     * Blocks to simulate a downstream call. Throws for a simulated outage,
     * sleeps beyond the caller's timeout for a simulated slow dependency, and
     * returns immediately when healthy.
     */
    public void simulateCall(Duration slowDelay) {
        switch (mode.get()) {
            case DOWN -> throw new IllegalStateException("Simulated downstream outage");
            case SLOW -> sleep(slowDelay);
            case HEALTHY -> { /* no delay */ }
        }
    }

    private void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while simulating downstream latency", exception);
        }
    }
}
