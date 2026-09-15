package com.example.spring.security.reference.commonsecurity;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPublicKey;

/**
 * Generates an in-process RSA key pair for the resource-server lab.
 *
 * A real deployment obtains verification material from a trusted issuer's JWK
 * set and never generates signing keys inside the resource server.
 */
@Component
public class JwtLabKeyProvider {

    public static final String KEY_ID = "lab-signing-key";

    private final RSAKey rsaKey;

    public JwtLabKeyProvider() {
        try {
            this.rsaKey = new RSAKeyGenerator(2048).keyID(KEY_ID).generate();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Unable to generate lab signing key", exception);
        }
    }

    public RSAKey rsaKey() {
        return rsaKey;
    }

    public RSAPublicKey publicKey() {
        try {
            return rsaKey.toRSAPublicKey();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Unable to read lab public key", exception);
        }
    }
}
