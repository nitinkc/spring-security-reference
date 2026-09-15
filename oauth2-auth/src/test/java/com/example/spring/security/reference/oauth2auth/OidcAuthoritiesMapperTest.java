package com.example.spring.security.reference.oauth2auth;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OidcAuthoritiesMapperTest {

    private final OidcAuthoritiesMapper mapper = new OidcAuthoritiesMapper();

    @Test
    void mapsListOfRolesToSpringAuthorities() {
        OidcUser user = oidcUserWithClaims(Map.of("roles", List.of("USER", "ADMIN")));

        Collection<? extends GrantedAuthority> authorities = mapper.mapAuthorities(user);

        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void mapsCommaSeparatedRolesToSpringAuthorities() {
        OidcUser user = oidcUserWithClaims(Map.of("roles", "user,admin"));

        Collection<? extends GrantedAuthority> authorities = mapper.mapAuthorities(user);

        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void assignsDefaultUserAuthorityWhenNoRolesClaim() {
        OidcUser user = oidcUserWithClaims(Map.of());

        Collection<? extends GrantedAuthority> authorities = mapper.mapAuthorities(user);

        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
    }

    private OidcUser oidcUserWithClaims(Map<String, Object> extraClaims) {
        Instant now = Instant.now();
        OidcIdToken idToken = new OidcIdToken("jwt", now, now.plusSeconds(60), Map.of("sub", "labuser"));
        Map<String, Object> userInfoClaims = new HashMap<>(extraClaims);
        userInfoClaims.putIfAbsent("sub", "labuser");
        OidcUserInfo userInfo = new OidcUserInfo(userInfoClaims);
        return new DefaultOidcUser(List.of(), idToken, userInfo, "sub");
    }
}
