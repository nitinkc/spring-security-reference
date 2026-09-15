package com.example.spring.security.reference.oauth2auth;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
public class CustomOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final OidcUserService delegate = new OidcUserService();
    private final OidcAuthoritiesMapper authoritiesMapper;

    public CustomOidcUserService(OidcAuthoritiesMapper authoritiesMapper) {
        this.authoritiesMapper = authoritiesMapper;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) {
        OidcUser oidcUser = delegate.loadUser(userRequest);
        Collection<? extends org.springframework.security.core.GrantedAuthority> mappedAuthorities =
                authoritiesMapper.mapAuthorities(oidcUser);

        OidcUserInfo userInfo = oidcUser.getUserInfo();
        if (userInfo == null) {
            userInfo = new OidcUserInfo(java.util.Map.of());
        }

        return new org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser(
                mappedAuthorities,
                userRequest.getIdToken(),
                userInfo,
                userRequest.getClientRegistration()
                        .getProviderDetails()
                        .getUserInfoEndpoint()
                        .getUserNameAttributeName());
    }
}
