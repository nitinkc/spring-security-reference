package com.example.spring.security.reference.graphqlservice;

import graphql.analysis.MaxQueryComplexityInstrumentation;
import graphql.analysis.MaxQueryDepthInstrumentation;
import graphql.execution.instrumentation.ChainedInstrumentation;
import org.springframework.boot.autoconfigure.graphql.GraphQlSourceBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class GraphQLConfig {

    @Bean
    public SecurityFilterChain graphQLSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll())
                .build();
    }

    @Bean
    public GraphQlSourceBuilderCustomizer graphQlSourceBuilderCustomizer() {
        return builder -> builder.configureGraphQl(graphQlBuilder ->
                graphQlBuilder.instrumentation(new ChainedInstrumentation(java.util.List.of(
                        new MaxQueryComplexityInstrumentation(3),
                        new MaxQueryDepthInstrumentation(5)))));
    }
}
