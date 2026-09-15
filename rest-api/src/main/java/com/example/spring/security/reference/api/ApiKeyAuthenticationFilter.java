package com.example.spring.security.reference.api;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Component
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    public static final String API_KEY_HEADER = "X-API-Key";

    private final ApiKeyRepository apiKeyRepository;
    private final ApiKeyRateLimiter rateLimiter;

    public ApiKeyAuthenticationFilter(ApiKeyRepository apiKeyRepository, ApiKeyRateLimiter rateLimiter) {
        this.apiKeyRepository = apiKeyRepository;
        this.rateLimiter = rateLimiter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/apikey/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String apiKey = request.getHeader(API_KEY_HEADER);
        if (apiKey == null || apiKey.isBlank()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        Optional<ApiKey> maybeKey = apiKeyRepository.findByKey(apiKey);
        if (maybeKey.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        ApiKey key = maybeKey.get();
        if (!rateLimiter.allow(apiKey, key.quotaPerWindow(), key.windowSeconds())) {
            response.setStatus(429);
            return;
        }

        List<SimpleGrantedAuthority> authorities = key.roles().stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
        ApiKeyAuthenticationToken authentication = new ApiKeyAuthenticationToken(key.name(), authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }
}
