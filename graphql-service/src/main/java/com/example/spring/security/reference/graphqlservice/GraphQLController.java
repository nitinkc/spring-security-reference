package com.example.spring.security.reference.graphqlservice;

import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.graphql.data.method.annotation.SchemaMapping;
import org.springframework.stereotype.Controller;

@Controller
public class GraphQLController {
    @QueryMapping
    public String hello() {
        return "Hello from GraphQL!";
    }
}
