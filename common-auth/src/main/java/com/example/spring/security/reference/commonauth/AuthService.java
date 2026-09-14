package com.example.spring.security.reference.commonauth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * AuthService handles user authentication (session, JWT, and hooks for 2FA)
 */
@Service
public class AuthService {
    private static final String DUMMY_PASSWORD = "{bcrypt}$2a$10$7EqJtq98hPqEX7fNZaFWoO5uWIIyJwVnxuQp76xUMCbfR8goWg9Kq";

    private final InMemoryCredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(InMemoryCredentialRepository credentialRepository, PasswordEncoder passwordEncoder) {
        this.credentialRepository = credentialRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Example: Authenticate with username/password
    public boolean authenticateSession(String username, String password) {
        // Validate against DB or user store
        var credential = credentialRepository.findByUsername(username);
        String encodedPassword = credential.map(InMemoryCredentialRepository.CredentialRecord::encodedPassword)
            .orElse(DUMMY_PASSWORD);
        boolean authenticated;
        try {
            authenticated = passwordEncoder.matches(password, encodedPassword);
        } catch (IllegalArgumentException exception) {
            authenticated = false;
        }

        if (authenticated && passwordEncoder.upgradeEncoding(encodedPassword)) {
            credentialRepository.updatePassword(username, passwordEncoder.encode(password));
        }

        return authenticated && credential.isPresent();
    }

    public String getRole(String username) {
        return credentialRepository.findByUsername(username)
            .map(InMemoryCredentialRepository.CredentialRecord::role)
            .orElseThrow();
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