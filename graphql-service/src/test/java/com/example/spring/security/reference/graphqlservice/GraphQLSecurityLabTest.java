package com.example.spring.security.reference.graphqlservice;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class GraphQLSecurityLabTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void helloReturnsGreeting() throws Exception {
        JsonNode result = execute("{ hello }");

        assert result.at("/data/hello").asText().equals("Hello from GraphQL");
        assert result.at("/errors").isMissingNode();
    }

    @Test
    void userCanReadOwnName() throws Exception {
        JsonNode result = execute("{ me { name } }");

        assert result.at("/data/me/name").asText().equals("alice");
        assert result.at("/errors").isMissingNode();
    }

    @Test
    @WithMockUser(roles = "USER")
    void userCannotReadSalary() throws Exception {
        JsonNode result = execute("{ me { name salary } }");

        assert result.at("/data/me/name").asText().equals("alice");
        assert result.at("/data/me/salary").isNull();
        assert !result.at("/errors").isMissingNode();
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void adminCanReadSalary() throws Exception {
        JsonNode result = execute("{ me { name salary } }");

        assert result.at("/data/me/name").asText().equals("alice");
        assert result.at("/data/me/salary").asInt() == 100_000;
        assert result.at("/errors").isMissingNode();
    }

    @Test
    void complexQueryIsRejected() throws Exception {
        JsonNode result = execute("{ hello me { name salary } }");

        assert result.at("/errors").isArray() && result.at("/errors").size() > 0;
    }

    private JsonNode execute(String query) throws Exception {
        MvcResult mvcResult = mockMvc.perform(post("/graphql")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"query\":\"" + query.replace("\"", "\\\"") + "\"}"))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readTree(mvcResult.getResponse().getContentAsString());
    }
}
