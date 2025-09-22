package com.example.spring.security.reference.commonauth;

import org.springframework.stereotype.Service;

/**
 * AuthService handles user authentication (session, JWT, and hooks for 2FA)
 */
@Service
public class AuthService {
    // Example: Authenticate with username/password
    public boolean authenticateSession(String username, String password) {
        // Validate against DB or user store
        return "admin".equals(username) && "password".equals(password);
    }

    // Example: Authenticate with JWT
    public boolean authenticateJwt(String username) {
        // Usually you'd check user existence, etc.
        return username != null;
    }

    // Placeholder for 2FA hook (TOTP)
    public boolean verify2FA(String username, String otp) {
        // Integrate with real TOTP provider
        return "123456".equals(otp);
    }
}