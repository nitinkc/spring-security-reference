package com.example.spring.security.reference.commonauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class AuthServicePasswordMigrationLabTest {

    private InMemoryCredentialRepository credentialRepository;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        credentialRepository = new InMemoryCredentialRepository(passwordEncoder);
        authService = new AuthService(credentialRepository, passwordEncoder);
    }

    @Test
    void currentPasswordIsStoredWithAnEncodingIdentifier() {
        String encodedPassword = credentialRepository.findByUsername("admin").orElseThrow().encodedPassword();

        assertThat(encodedPassword)
            .startsWith("{bcrypt}")
            .doesNotContain("{bcrypt}password");
        assertThat(authService.authenticateSession("admin", "password")).isTrue();
    }

    @Test
    void plaintextValueIsNotAcceptedAsAStoredPassword() {
        credentialRepository.updatePassword("admin", "password");

        assertThat(authService.authenticateSession("admin", "password")).isFalse();
    }

    @Test
    void successfulAuthenticationUpgradesALegacyEncoding() {
        assertThat(credentialRepository.findByUsername("user").orElseThrow().encodedPassword())
            .isEqualTo("{noop}password");

        assertThat(authService.authenticateSession("user", "password")).isTrue();

        assertThat(credentialRepository.findByUsername("user").orElseThrow().encodedPassword())
            .startsWith("{bcrypt}")
            .isNotEqualTo("{noop}password");
    }

    @Test
    void failedAuthenticationDoesNotUpgradeTheStoredHash() {
        assertThat(authService.authenticateSession("user", "wrong")).isFalse();

        assertThat(credentialRepository.findByUsername("user").orElseThrow().encodedPassword())
            .isEqualTo("{noop}password");
    }
}
