package com.example.spring.security.reference.api;

import java.time.Instant;
import java.util.List;

public record SecureApiKey(String id,
                           String subject,
                           String prefix,
                           String secretHash,
                           String salt,
                           List<String> scopes,
                           Instant issuedAt,
                           Instant expiresAt,
                           Instant revokedAt,
                           Instant graceExpiresAt) {
}
