package com.example.spring.security.reference.graphqlservice;

import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.graphql.data.method.annotation.SchemaMapping;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;

import java.util.Map;

@Controller
public class GraphQLController {

    private final Map<String, Integer> salaries = Map.of("alice", 100_000);

    @QueryMapping
    public String hello() {
        return "Hello from GraphQL";
    }

    @QueryMapping
    public User me() {
        return new User("alice");
    }

    @SchemaMapping
    @PreAuthorize("hasRole('ADMIN')")
    public Integer salary(User user) {
        return salaries.get(user.name());
    }
}
