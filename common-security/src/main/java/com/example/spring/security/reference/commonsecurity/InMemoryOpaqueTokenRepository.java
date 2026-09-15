package com.example.spring.security.reference.commonsecurity;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory learning store for opaque (reference) access tokens.
 *
 * A real implementation stores only hashes and metadata in a database or cache.
 * Tokens must never be stored in plain text in a production system.
 */
public class InMemoryOpaqueTokenRepository {

    private final Map<String, OpaqueTokenRecord> tokens = new ConcurrentHashMap<>();

    public String issue(String subject, String clientId, Instant expiresAt, String... scopes) {
        String tokenValue = UUID.randomUUID().toString();
        tokens.put(tokenValue, new OpaqueTokenRecord(tokenValue, subject, clientId, expiresAt, true, scopes));
        return tokenValue;
    }

    public OpaqueTokenRecord introspect(String tokenValue) {
        OpaqueTokenRecord record = tokens.get(tokenValue);
        if (record == null) {
            return null;
        }
        if (record.expiresAt.isBefore(Instant.now())) {
            return new OpaqueTokenRecord(record.value, record.subject, record.clientId,
                record.expiresAt, false, record.scopes);
        }
        return record;
    }

    public boolean revoke(String tokenValue) {
        OpaqueTokenRecord record = tokens.remove(tokenValue);
        return record != null;
    }

    public record OpaqueTokenRecord(String value,
                                    String subject,
                                    String clientId,
                                    Instant expiresAt,
                                    boolean active,
                                    String[] scopes) {}
}
