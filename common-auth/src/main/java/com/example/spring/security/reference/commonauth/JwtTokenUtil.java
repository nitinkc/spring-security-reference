package com.example.spring.security.reference.commonauth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import org.springframework.stereotype.Component;
import java.util.Date;
import javax.crypto.SecretKey;

/**
 * Utility class for JWT token creation and validation.
 *
 * Uses cryptographically secure keys for HS512 algorithm.
 * The signing key is generated using Keys.secretKeyFor() which ensures
 * the key is at least 512 bits (64 bytes) as required by HS512.
 */
@Component
public class JwtTokenUtil {
    // Generate a secure 512-bit key for HS512 algorithm
    // This prevents "WeakKeyException: The signing key's size is X bits which is not secure enough for the HS512 algorithm"
    private static final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    private static final long EXPIRATION_TIME = 86400000; // 1 day

    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();
    }

    public Claims getClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token, String username) {
        Claims claims = getClaimsFromToken(token);
        return claims.getSubject().equals(username) && claims.getExpiration().after(new Date());
    }
}