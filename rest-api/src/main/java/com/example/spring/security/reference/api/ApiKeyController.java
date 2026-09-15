package com.example.spring.security.reference.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.stream.Collectors;

@RestController
public class ApiKeyController {

    @GetMapping("/apikey/user")
    public String user(Principal principal) {
        return "API key user: " + principal.getName();
    }

    @GetMapping("/apikey/admin")
    public String admin(Principal principal, org.springframework.security.core.Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(org.springframework.security.core.GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        return "API key admin: " + principal.getName() + " [" + authorities + "]";
    }
}
