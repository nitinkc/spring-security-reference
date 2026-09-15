package com.example.spring.security.reference.samlauth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.web.SecurityFilterChain;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

@Configuration
@EnableWebSecurity
public class SamlAuthConfig {

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository(
            @Value("classpath:saml/idp-metadata.xml") Resource idpMetadata,
            @Value("classpath:saml/sp-cert.der") Resource spCertificate,
            @Value("classpath:saml/sp-key.der") Resource spPrivateKey
    ) throws Exception {
        X509Certificate certificate = readCertificate(spCertificate);
        PrivateKey privateKey = readPrivateKey(spPrivateKey);
        Saml2X509Credential signing = new Saml2X509Credential(
                privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING);
        Saml2X509Credential decryption = new Saml2X509Credential(
                privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.DECRYPTION);

        try (InputStream metadata = idpMetadata.getInputStream()) {
            RelyingPartyRegistration registration = RelyingPartyRegistrations
                    .fromMetadata(metadata)
                    .registrationId("lab-idp")
                    .signingX509Credentials(c -> c.add(signing))
                    .decryptionX509Credentials(c -> c.add(decryption))
                    .build();
            return new InMemoryRelyingPartyRegistrationRepository(registration);
        }
    }

    @Bean
    public SecurityFilterChain samlSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/saml/**", "/login/saml2/**", "/logout/saml2/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/saml/public").permitAll()
                        .anyRequest().authenticated()
                )
                .saml2Login(saml2 -> saml2
                        .loginProcessingUrl("/login/saml2/sso/lab-idp")
                        .defaultSuccessUrl("/saml/welcome", true)
                )
                .saml2Logout(logout -> logout
                        .logoutRequest(req -> req.logoutUrl("/logout/saml2/lab-idp"))
                );
        return http.build();
    }

    private static X509Certificate readCertificate(Resource resource) throws Exception {
        try (InputStream is = resource.getInputStream()) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(is);
        }
    }

    private static PrivateKey readPrivateKey(Resource resource) throws Exception {
        try (InputStream is = resource.getInputStream()) {
            byte[] keyBytes = is.readAllBytes();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        }
    }
}
