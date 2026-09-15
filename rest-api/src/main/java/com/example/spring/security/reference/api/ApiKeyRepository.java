package com.example.spring.security.reference.api;

import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class ApiKeyRepository {

    private final Map<String, ApiKey> keys = new ConcurrentHashMap<>();

    public ApiKeyRepository() {
        keys.put("api-key-user", new ApiKey("user-key", java.util.List.of("ROLE_USER"), 10, 1));
        keys.put("api-key-admin", new ApiKey("admin-key", java.util.List.of("ROLE_ADMIN"), 10, 1));
    }

    public Optional<ApiKey> findByKey(String key) {
        return Optional.ofNullable(keys.get(key));
    }
}
