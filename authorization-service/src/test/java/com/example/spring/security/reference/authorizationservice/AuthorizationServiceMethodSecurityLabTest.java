package com.example.spring.security.reference.authorizationservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringJUnitConfig({MethodSecurityConfig.class, AuthorizationService.class})
class AuthorizationServiceMethodSecurityLabTest {

    @Autowired
    private AuthorizationService authorizationService;

    @Test
    void anonymousCallerCannotInvokeAdminOperation() {
        assertThatThrownBy(authorizationService::adminOperation)
            .isInstanceOf(AuthenticationCredentialsNotFoundException.class);
    }

    @Test
    @WithMockUser(roles = "USER")
    void userCannotInvokeAdminOperation() {
        assertThatThrownBy(authorizationService::adminOperation)
            .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void adminCanInvokeAdminOperation() {
        assertThat(authorizationService.adminOperation()).isEqualTo("admin-operation");
    }

    @Test
    @WithMockUser(username = "user", roles = "USER")
    void ownerCanReadOwnProfile() {
        assertThat(authorizationService.readProfile("user")).isEqualTo("profile:user");
    }

    @Test
    @WithMockUser(username = "user", roles = "USER")
    void userCannotReadAnotherProfile() {
        assertThatThrownBy(() -> authorizationService.readProfile("other"))
            .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    void adminCanReadAnotherProfile() {
        assertThat(authorizationService.readProfile("user")).isEqualTo("profile:user");
    }
}
