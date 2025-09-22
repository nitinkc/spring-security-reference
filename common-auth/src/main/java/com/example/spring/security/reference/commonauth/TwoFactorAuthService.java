package com.example.spring.security.reference.commonauth;

import org.springframework.stereotype.Service;

/**
 * Example TOTP/2FA service hook. Replace with a real implementation.
 */
@Service
public class TwoFactorAuthService {
    public boolean verifyTOTP(String username, String otp) {
        // Integrate with real TOTP library or service
        return "654321".equals(otp);
    }
}