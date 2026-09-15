package com.example.spring.security.reference.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ApiKeyLifecycleLabTest {

    @Autowired
    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void activeUserKeySucceeds() throws Exception {
        String fullKey = issueKey("alice", "USER");

        mockMvc.perform(get("/apikey-life/user").header(SecureApiKeyAuthenticationFilter.API_KEY_HEADER, fullKey))
                .andExpect(status().isOk())
                .andExpect(content().string("secure-api-key user"));
    }

    @Test
    void activeAdminKeySucceeds() throws Exception {
        String fullKey = issueKey("bob", "ADMIN");

        mockMvc.perform(get("/apikey-life/admin").header(SecureApiKeyAuthenticationFilter.API_KEY_HEADER, fullKey))
                .andExpect(status().isOk())
                .andExpect(content().string("secure-api-key admin"));
    }

    @Test
    void wrongScopeIsDenied() throws Exception {
        String fullKey = issueKey("alice", "USER");

        mockMvc.perform(get("/apikey-life/admin").header(SecureApiKeyAuthenticationFilter.API_KEY_HEADER, fullKey))
                .andExpect(status().isForbidden());
    }

    @Test
    void expiredKeyIsRejected() throws Exception {
        String fullKey = issueExpiredKey("carol", "USER");

        mockMvc.perform(get("/apikey-life/user").header(SecureApiKeyAuthenticationFilter.API_KEY_HEADER, fullKey))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void revokedKeyIsRejected() throws Exception {
        Map<String, Object> issue = issueAndReturnMap("dave", "USER");
        String fullKey = (String) issue.get("fullKey");
        String prefix = (String) issue.get("prefix");

        mockMvc.perform(post("/apikey-life/revoke").param("prefix", prefix))
                .andExpect(status().isOk());

        mockMvc.perform(get("/apikey-life/user").header(SecureApiKeyAuthenticationFilter.API_KEY_HEADER, fullKey))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unknownOrTamperedKeyIsRejected() throws Exception {
        mockMvc.perform(get("/apikey-life/user")
                        .header(SecureApiKeyAuthenticationFilter.API_KEY_HEADER, "badprefix.wrongsecret"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rotationAllowsGraceThenRevokesOldKey() throws Exception {
        Map<String, Object> issue = issueAndReturnMap("ellen", "USER");
        String oldKey = (String) issue.get("fullKey");
        String prefix = (String) issue.get("prefix");

        mockMvc.perform(get("/apikey-life/user").header(SecureApiKeyAuthenticationFilter.API_KEY_HEADER, oldKey))
                .andExpect(status().isOk());

        String json = mockMvc.perform(post("/apikey-life/rotate").param("prefix", prefix))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        Map<String, Object> rotate = objectMapper.readValue(json, Map.class);
        String newKey = (String) rotate.get("fullKey");

        mockMvc.perform(get("/apikey-life/user").header(SecureApiKeyAuthenticationFilter.API_KEY_HEADER, oldKey))
                .andExpect(status().isOk());
        mockMvc.perform(get("/apikey-life/user").header(SecureApiKeyAuthenticationFilter.API_KEY_HEADER, newKey))
                .andExpect(status().isOk());

        Thread.sleep(1_200);

        mockMvc.perform(get("/apikey-life/user").header(SecureApiKeyAuthenticationFilter.API_KEY_HEADER, oldKey))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/apikey-life/user").header(SecureApiKeyAuthenticationFilter.API_KEY_HEADER, newKey))
                .andExpect(status().isOk());
    }

    private String issueKey(String subject, String scopes) throws Exception {
        return (String) issueAndReturnMap(subject, scopes).get("fullKey");
    }

    private String issueExpiredKey(String subject, String scopes) throws Exception {
        String json = mockMvc.perform(post("/apikey-life/issue-expired")
                        .param("subject", subject)
                        .param("scopes", scopes))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return (String) objectMapper.readValue(json, Map.class).get("fullKey");
    }

    private Map<String, Object> issueAndReturnMap(String subject, String scopes) throws Exception {
        String json = mockMvc.perform(post("/apikey-life/issue")
                        .param("subject", subject)
                        .param("scopes", scopes))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readValue(json, Map.class);
    }
}
