package com.example.spring.security.reference.samlauth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SamlPublicController {

    @GetMapping("/saml/public")
    public String greeting() {
        return "SAML reference application";
    }

    @GetMapping("/saml/welcome")
    public String welcome() {
        return "Welcome, authenticated user";
    }
}
