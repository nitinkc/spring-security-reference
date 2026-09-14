package com.example.spring.security.reference.commonauth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class InMemoryCredentialRepository {

    private final Map<String, CredentialRecord> credentials = new ConcurrentHashMap<>();

    public InMemoryCredentialRepository(PasswordEncoder passwordEncoder) {
        credentials.put("admin", new CredentialRecord(passwordEncoder.encode("password"), "ROLE_ADMIN"));
        credentials.put("user", new CredentialRecord("{noop}password", "ROLE_USER"));
    }

    Optional<CredentialRecord> findByUsername(String username) {
        return Optional.ofNullable(credentials.get(username));
    }

    void updatePassword(String username, String encodedPassword) {
        credentials.computeIfPresent(username, (key, record) ->
            new CredentialRecord(encodedPassword, record.role()));
    }

    record CredentialRecord(String encodedPassword, String role) {
    }
}
