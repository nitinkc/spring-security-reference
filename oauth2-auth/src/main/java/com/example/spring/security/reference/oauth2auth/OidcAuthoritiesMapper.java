package com.example.spring.security.reference.oauth2auth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
public class OidcAuthoritiesMapper {

    Collection<? extends GrantedAuthority> mapAuthorities(OidcUser source) {
        Set<GrantedAuthority> mapped = new HashSet<>();

        Object roles = source.getAttributes().get("roles");
        if (roles instanceof List<?> roleList) {
            for (Object role : roleList) {
                if (role instanceof String r && !r.isBlank()) {
                    mapped.add(new SimpleGrantedAuthority("ROLE_" + r.toUpperCase()));
                }
            }
        } else if (roles instanceof String roleString && !roleString.isBlank()) {
            for (String r : roleString.split(",")) {
                mapped.add(new SimpleGrantedAuthority("ROLE_" + r.trim().toUpperCase()));
            }
        }

        if (mapped.isEmpty()) {
            mapped.add(new SimpleGrantedAuthority("ROLE_USER"));
        }

        return mapped;
    }
}
