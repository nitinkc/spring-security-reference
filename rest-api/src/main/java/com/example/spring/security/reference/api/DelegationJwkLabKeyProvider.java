package com.example.spring.security.reference.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.stereotype.Component;

/**
 * Single-issuer RSA key pair for the delegated-access lab. A real deployment
 * would use the identity provider's published JWK set, not an in-process key.
 */
@Component
public class DelegationJwkLabKeyProvider {

    private static final String KEY_ID = "delegation-lab-signing-key";

    private final RSAKey key;

    public DelegationJwkLabKeyProvider() {
        try {
            key = new RSAKeyGenerator(2048).keyID(KEY_ID).generate();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Unable to generate delegation lab signing key", exception);
        }
    }

    public RSAKey rsaKey() {
        return key;
    }

    public JWKSet jwkSet() {
        return new JWKSet(key);
    }
}
