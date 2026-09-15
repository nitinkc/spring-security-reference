package com.example.spring.security.reference.commonsecurity;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * In-process opaque token introspector for the lab.
 *
 * A real resource server would call an IdP introspection endpoint over HTTPS
 * with Basic or Bearer client credentials.
 */
public class LocalOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final InMemoryOpaqueTokenRepository repository;

    public LocalOpaqueTokenIntrospector(InMemoryOpaqueTokenRepository repository) {
        this.repository = repository;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        InMemoryOpaqueTokenRepository.OpaqueTokenRecord record = repository.introspect(token);

        if (record == null || !record.active()) {
            throw new org.springframework.security.oauth2.server.resource.InvalidBearerTokenException(
                "Token is not active");
        }

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", record.subject());
        attributes.put("client_id", record.clientId());
        attributes.put("active", true);
        attributes.put("exp", record.expiresAt());

        List<GrantedAuthority> authorities = Arrays.stream(record.scopes())
            .map(scope -> (GrantedAuthority) new SimpleGrantedAuthority("SCOPE_" + scope.toUpperCase()))
            .toList();

        return new DefaultOAuth2AuthenticatedPrincipal(record.subject(), attributes, authorities);
    }
}
