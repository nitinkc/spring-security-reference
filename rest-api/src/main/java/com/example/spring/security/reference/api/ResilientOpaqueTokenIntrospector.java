package com.example.spring.security.reference.api;

import com.example.spring.security.reference.commonsecurity.InMemoryOpaqueTokenRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Wraps opaque-token introspection with a bounded timeout and a short-lived
 * cache of previously verified results, so a downstream outage fails closed
 * for unseen tokens while allowing brief continuity for tokens verified
 * moments earlier.
 *
 * This is a fail-secure degraded mode, not a fail-open one: an unknown token
 * is always rejected when the dependency cannot be reached in time.
 */
@Component
public class ResilientOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private static final Duration CALL_TIMEOUT = Duration.ofMillis(200);
    private static final Duration CACHE_TTL = Duration.ofSeconds(5);

    private final InMemoryOpaqueTokenRepository repository;
    private final DependencyOutageSimulator outageSimulator;
    private final Map<String, CachedResult> cache = new ConcurrentHashMap<>();

    public ResilientOpaqueTokenIntrospector(InMemoryOpaqueTokenRepository repository,
                                             DependencyOutageSimulator outageSimulator) {
        this.repository = repository;
        this.outageSimulator = outageSimulator;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        try {
            OAuth2AuthenticatedPrincipal principal = callDownstreamWithTimeout(token);
            cache.put(token, new CachedResult(principal, Instant.now().plus(CACHE_TTL)));
            return principal;
        } catch (TimeoutException | ExecutionException | InterruptedException | IllegalStateException exception) {
            if (exception instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            CachedResult cached = cache.get(token);
            if (cached != null && cached.expiresAt().isAfter(Instant.now())) {
                return cached.principal();
            }
            throw new BadOpaqueTokenException(
                    "Introspection dependency unavailable and no cached result for this token", exception);
        }
    }

    private OAuth2AuthenticatedPrincipal callDownstreamWithTimeout(String token)
            throws TimeoutException, ExecutionException, InterruptedException {
        CompletableFuture<OAuth2AuthenticatedPrincipal> future = CompletableFuture.supplyAsync(
                () -> doIntrospect(token));
        return future.get(CALL_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
    }

    private OAuth2AuthenticatedPrincipal doIntrospect(String token) {
        outageSimulator.simulateCall(CALL_TIMEOUT.multipliedBy(5));

        InMemoryOpaqueTokenRepository.OpaqueTokenRecord record = repository.introspect(token);
        if (record == null || !record.active()) {
            throw new BadOpaqueTokenException("Token is not active");
        }

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", record.subject());
        attributes.put("client_id", record.clientId());
        attributes.put("active", true);
        attributes.put("exp", record.expiresAt());

        List<GrantedAuthority> authorities = java.util.Arrays.stream(record.scopes())
                .map(scope -> (GrantedAuthority) new org.springframework.security.core.authority.SimpleGrantedAuthority(
                        "SCOPE_" + scope.toUpperCase()))
                .toList();

        return new DefaultOAuth2AuthenticatedPrincipal(record.subject(), attributes, authorities);
    }

    void clearCache() {
        cache.clear();
    }

    private record CachedResult(OAuth2AuthenticatedPrincipal principal, Instant expiresAt) {
    }
}
