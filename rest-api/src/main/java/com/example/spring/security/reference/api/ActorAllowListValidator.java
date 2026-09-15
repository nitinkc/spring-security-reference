package com.example.spring.security.reference.api;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Map;
import java.util.Set;

/**
 * Enforces that a delegated (actor) token's {@code act.sub} claim, when
 * present, identifies a trusted actor. This prevents any client that can
 * produce an "act" claim from impersonating a user through an untrusted
 * intermediary.
 */
public class ActorAllowListValidator implements OAuth2TokenValidator<Jwt> {

    private final Set<String> trustedActors;

    public ActorAllowListValidator(Set<String> trustedActors) {
        this.trustedActors = trustedActors;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        Map<String, Object> actClaim = token.getClaimAsMap("act");
        if (actClaim == null) {
            return OAuth2TokenValidatorResult.success();
        }

        Object actorSubject = actClaim.get("sub");
        if (!(actorSubject instanceof String actor) || !trustedActors.contains(actor)) {
            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("untrusted_actor", "Actor is not in the trusted delegation allow-list", null));
        }

        return OAuth2TokenValidatorResult.success();
    }
}
