package com.example.spring.security.reference.api;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SecureApiKeyService {

    private static final Duration DEFAULT_TTL = Duration.ofMinutes(5);
    private static final Duration DEFAULT_ROTATION_GRACE = Duration.ofSeconds(1);

    private final Map<String, SecureApiKey> keysByPrefix = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public record IssueResult(String fullKey, String prefix) {
    }

    public IssueResult issue(String subject, List<String> scopes) {
        return issue(subject, scopes, DEFAULT_TTL, null);
    }

    public IssueResult issue(String subject, List<String> scopes, Duration ttl, Instant fixedExpiry) {
        String prefix = randomHex(8);
        String secret = randomHex(32);
        String salt = randomHex(16);
        String secretHash = hash(secret, salt);

        Instant now = Instant.now();
        Instant expiresAt = fixedExpiry != null ? fixedExpiry : now.plus(ttl);

        SecureApiKey key = new SecureApiKey(
                UUID.randomUUID().toString(),
                subject,
                prefix,
                secretHash,
                salt,
                scopes,
                now,
                expiresAt,
                null,
                null);

        keysByPrefix.put(prefix, key);
        return new IssueResult(prefix + "." + secret, prefix);
    }

    public IssueResult rotate(String prefix) {
        SecureApiKey old = keysByPrefix.get(prefix);
        if (old == null) {
            throw new BadCredentialsException("Unknown key");
        }

        IssueResult next = issue(old.subject(), old.scopes(), DEFAULT_TTL, null);

        SecureApiKey rotatedOld = new SecureApiKey(
                old.id(),
                old.subject(),
                old.prefix(),
                old.secretHash(),
                old.salt(),
                old.scopes(),
                old.issuedAt(),
                old.expiresAt(),
                old.revokedAt(),
                Instant.now().plus(DEFAULT_ROTATION_GRACE));

        keysByPrefix.put(prefix, rotatedOld);
        return next;
    }

    public boolean revoke(String prefix) {
        SecureApiKey old = keysByPrefix.get(prefix);
        if (old == null) {
            return false;
        }

        SecureApiKey revoked = new SecureApiKey(
                old.id(),
                old.subject(),
                old.prefix(),
                old.secretHash(),
                old.salt(),
                old.scopes(),
                old.issuedAt(),
                old.expiresAt(),
                Instant.now(),
                old.graceExpiresAt());

        keysByPrefix.put(prefix, revoked);
        return true;
    }

    public SecureApiKey validate(String fullKey) {
        int dot = fullKey.indexOf('.');
        if (dot <= 0 || dot == fullKey.length() - 1) {
            throw new BadCredentialsException("Malformed API key");
        }

        String prefix = fullKey.substring(0, dot);
        String secret = fullKey.substring(dot + 1);

        SecureApiKey key = keysByPrefix.get(prefix);
        if (key == null) {
            throw new BadCredentialsException("Unknown API key");
        }

        Instant now = Instant.now();
        if (key.revokedAt() != null) {
            throw new BadCredentialsException("Revoked API key");
        }
        if (key.expiresAt() != null && key.expiresAt().isBefore(now)) {
            throw new BadCredentialsException("Expired API key");
        }
        if (key.graceExpiresAt() != null && key.graceExpiresAt().isBefore(now)) {
            throw new BadCredentialsException("Rotated API key grace period expired");
        }

        String computed = hash(secret, key.salt());
        if (!MessageDigest.isEqual(computed.getBytes(StandardCharsets.UTF_8),
                key.secretHash().getBytes(StandardCharsets.UTF_8))) {
            throw new BadCredentialsException("Invalid API key");
        }

        return key;
    }

    private String hash(String secret, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] hash = digest.digest(secret.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 not available", exception);
        }
    }

    private String randomHex(int bytes) {
        byte[] value = new byte[bytes];
        random.nextBytes(value);
        return HexFormat.of().formatHex(value);
    }
}
