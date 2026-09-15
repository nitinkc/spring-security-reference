package com.example.spring.security.reference.samlauth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.test.web.servlet.MockMvc;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SamlRelyingPartyLabTest {

    @Autowired
    private RelyingPartyRegistrationRepository registrations;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void registrationIsLoadedFromMetadata() {
        RelyingPartyRegistration registration = registrations.findByRegistrationId("lab-idp");

        assertThat(registration).isNotNull();
        assertThat(registration.getRegistrationId()).isEqualTo("lab-idp");
        assertThat(registration.getAssertingPartyDetails().getEntityId()).isEqualTo("local:test:idp");
        assertThat(registration.getAssertingPartyDetails().getSingleSignOnServiceLocation())
                .isEqualTo("http://localhost:8090/auth/realms/spring-security-reference/protocol/saml");
        assertThat(registration.getSigningX509Credentials()).isNotEmpty();
        assertThat(registration.getDecryptionX509Credentials()).isNotEmpty();
    }

    @Test
    void serviceProviderHasLocalCredentials() {
        RelyingPartyRegistration registration = registrations.findByRegistrationId("lab-idp");

        assertThat(registration.getSigningX509Credentials()).hasSize(1);
        assertThat(registration.getDecryptionX509Credentials()).hasSize(1);

        X509Certificate certificate = (X509Certificate) registration.getSigningX509Credentials()
                .stream()
                .findFirst()
                .orElseThrow()
                .getCertificate();
        assertThat(certificate.getSubjectX500Principal().getName()).contains("spring-security-reference-sp");
    }

    @Test
    void samlLoginProtectedEndpointRedirectsToProvider() throws Exception {
        mockMvc.perform(get("/saml/welcome"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/saml2/authenticate?registrationId=lab-idp"));
    }

    @Test
    void publicEndpointIsReachableWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/saml/public"))
                .andExpect(status().isOk())
                .andExpect(content().string("SAML reference application"));
    }
}
