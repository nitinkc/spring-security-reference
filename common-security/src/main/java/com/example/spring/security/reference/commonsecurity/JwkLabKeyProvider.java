package com.example.spring.security.reference.commonsecurity;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Generates and rotates in-process RSA key pairs for the JWK rotation lab.
 *
 * Real deployments obtain keys from an issuer's JWK set and rotate on a
 * schedule, never generating signing keys inside the resource server.
 */
@Component
public class JwkLabKeyProvider {

    public static final String CURRENT_KEY_ID = "lab-signing-key-current";
    public static final String PREVIOUS_KEY_ID = "lab-signing-key-previous";

    private final List<RSAKey> keys = new ArrayList<>();

    public JwkLabKeyProvider() {
        try {
            keys.add(new RSAKeyGenerator(2048).keyID(CURRENT_KEY_ID).generate());
            keys.add(new RSAKeyGenerator(2048).keyID(PREVIOUS_KEY_ID).generate());
        } catch (JOSEException exception) {
            throw new IllegalStateException("Unable to generate lab signing keys", exception);
        }
    }

    public JWKSet jwkSet() {
        List<JWK> jwks = new ArrayList<>(keys);
        return new JWKSet(jwks);
    }

    public RSAKey rsaKey(String keyId) {
        return keys.stream()
            .filter(key -> key.getKeyID().equals(keyId))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Unknown key id: " + keyId));
    }

    public RSAKey currentKey() {
        return rsaKey(CURRENT_KEY_ID);
    }

    public RSAKey previousKey() {
        return rsaKey(PREVIOUS_KEY_ID);
    }

    public RSAPublicKey publicKey(String keyId) {
        try {
            return rsaKey(keyId).toRSAPublicKey();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Unable to read public key: " + keyId, exception);
        }
    }
}
