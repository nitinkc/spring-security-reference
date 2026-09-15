package com.example.spring.security.reference.api;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TenantController {

    @GetMapping("/tenant/data")
    public String data(@AuthenticationPrincipal Jwt jwt) {
        String tenant = jwt.getClaimAsString("tenant");
        return "data for " + tenant;
    }
}
