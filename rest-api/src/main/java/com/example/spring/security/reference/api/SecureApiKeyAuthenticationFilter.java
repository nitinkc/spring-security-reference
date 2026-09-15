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

@Component
public class SecureApiKeyAuthenticationFilter extends OncePerRequestFilter {

    public static final String API_KEY_HEADER = "X-API-Key";

    private final SecureApiKeyService apiKeyService;

    public SecureApiKeyAuthenticationFilter(SecureApiKeyService apiKeyService) {
        this.apiKeyService = apiKeyService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/apikey-life/user")
                && !request.getRequestURI().startsWith("/apikey-life/admin");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String apiKey = request.getHeader(API_KEY_HEADER);
        if (apiKey == null || apiKey.isBlank()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        SecureApiKey key;
        try {
            key = apiKeyService.validate(apiKey);
        } catch (org.springframework.security.authentication.BadCredentialsException exception) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        List<SimpleGrantedAuthority> authorities = key.scopes().stream()
                .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope.toUpperCase()))
                .toList();

        SecureApiKeyAuthenticationToken authentication = new SecureApiKeyAuthenticationToken(key.subject(), authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }
}
