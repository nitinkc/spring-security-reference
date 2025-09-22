package com.example.spring.security.reference.authorizationservice;

import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * AuthorizationService manages users, roles, and permissions.
 */
@Service
public class AuthorizationService {
    private static final Map<String, String> userRoles = new HashMap<>();

    static {
        userRoles.put("admin", "ROLE_ADMIN");
        userRoles.put("user", "ROLE_USER");
    }

    public String getUserRole(String username) {
        return userRoles.getOrDefault(username, "ROLE_GUEST");
    }

    public boolean hasPermission(String username, String permission) {
        // Example: check if user has permission
        String role = getUserRole(username);
        return ("ROLE_ADMIN".equals(role) && "WRITE".equals(permission))
                || ("ROLE_USER".equals(role) && "READ".equals(permission));
    }
}