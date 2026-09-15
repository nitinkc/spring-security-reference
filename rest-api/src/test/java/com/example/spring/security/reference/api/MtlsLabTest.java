package com.example.spring.security.reference.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class MtlsLabTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void userCertificateIsAccepted() throws Exception {
        X509Certificate certificate = loadCertificate("mtls-user-cert.pem");

        mockMvc.perform(get("/mtls/user").with(x509Certificate(certificate)))
                .andExpect(status().isOk())
                .andExpect(content().string("mTLS user: mtls-user"));
    }

    @Test
    void adminCertificateIsAccepted() throws Exception {
        X509Certificate certificate = loadCertificate("mtls-admin-cert.pem");

        mockMvc.perform(get("/mtls/admin").with(x509Certificate(certificate)))
                .andExpect(status().isOk())
                .andExpect(content().string("mTLS admin: mtls-admin [ROLE_ADMIN]"));
    }

    @Test
    void userCertificateCannotAccessAdminRoute() throws Exception {
        X509Certificate certificate = loadCertificate("mtls-user-cert.pem");

        mockMvc.perform(get("/mtls/admin").with(x509Certificate(certificate)))
                .andExpect(status().isForbidden());
    }

    @Test
    void missingCertificateIsRejected() throws Exception {
        mockMvc.perform(get("/mtls/user"))
                .andExpect(status().is4xxClientError());
    }

    private static X509Certificate loadCertificate(String name) throws Exception {
        try (InputStream is = new ClassPathResource(name).getInputStream()) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(is);
        }
    }

    private static RequestPostProcessor x509Certificate(X509Certificate certificate) {
        return request -> {
            request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[]{certificate});
            return request;
        };
    }
}
