package com.example.spring.security.reference.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.stream.Collectors;

@RestController
public class MtlsController {

    @GetMapping("/mtls/user")
    public String user(Principal principal) {
        return "mTLS user: " + principal.getName();
    }

    @GetMapping("/mtls/admin")
    public String admin(Principal principal, org.springframework.security.core.Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(org.springframework.security.core.GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        return "mTLS admin: " + principal.getName() + " [" + authorities + "]";
    }
}
