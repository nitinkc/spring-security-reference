package com.example.spring.security.reference.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class TenantJwkLabKeyProvider {

    private static final List<String> TENANTS = List.of("tenant-a", "tenant-b");

    private final Map<String, RSAKey> keys = new ConcurrentHashMap<>();

    public TenantJwkLabKeyProvider() {
        try {
            for (String tenant : TENANTS) {
                keys.put(tenant, new RSAKeyGenerator(2048).keyID(tenant + "-signing-key").generate());
            }
        } catch (JOSEException exception) {
            throw new IllegalStateException("Unable to generate tenant lab signing keys", exception);
        }
    }

    public JWKSet jwkSet(String tenant) {
        return new JWKSet(List.<JWK>of(keys.get(tenant)));
    }

    public RSAKey rsaKey(String tenant) {
        RSAKey key = keys.get(tenant);
        if (key == null) {
            throw new IllegalArgumentException("Unknown tenant: " + tenant);
        }
        return key;
    }

    public List<String> tenants() {
        return TENANTS;
    }
}
