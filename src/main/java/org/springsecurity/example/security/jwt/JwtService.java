package org.springsecurity.example.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtService {
    private static final int MIN_SECRET_BYTES = 32;
    private static final String TOKEN_TYPE_CLAIM = "token_type";

    private final SecretKey signingKey;

    @Getter
    private final long accessExpirationMs;

    private final long refreshExpirationMs;

    public JwtService(
            @Value("${jwt.secret}") String encodedSecret,
            @Value("${jwt.access-token-expiration}") long accessExpirationMs,
            @Value("${jwt.refresh-token-expiration}") long refreshExpirationMs
    ) {
        this.signingKey = createSigningKey(encodedSecret);
        this.accessExpirationMs = accessExpirationMs;
        this.refreshExpirationMs = refreshExpirationMs;
    }

    private SecretKey createSigningKey(String encodedSecret) {
        final byte[] secretBytes;
        try {
            secretBytes = Decoders.BASE64.decode(encodedSecret);
        } catch (DecodingException | IllegalArgumentException exception) {
            throw new IllegalStateException("JWT_SECRET must be a valid Base64 value", exception);
        }

        if (secretBytes.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException(
                    "JWT_SECRET must contain at least 256 bits (32 bytes) of entropy"
            );
        }

        return Keys.hmacShaKeyFor(secretBytes);
    }

    public String generateAccessToken(UserDetails userDetails) {
        return buildToken(userDetails, accessExpirationMs, JwtTokenType.ACCESS);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(userDetails, refreshExpirationMs, JwtTokenType.REFRESH);
    }

    private String buildToken(UserDetails userDetails, long expirationMs, JwtTokenType tokenType) {
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(userDetails.getUsername())
                .claim(TOKEN_TYPE_CLAIM, tokenType.getClaimValue())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(signingKey)
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    public JwtTokenType extractTokenType(String token) {
        String claimValue = extractClaims(token).get(TOKEN_TYPE_CLAIM, String.class);
        for (JwtTokenType tokenType : JwtTokenType.values()) {
            if (tokenType.getClaimValue().equals(claimValue)) {
                return tokenType;
            }
        }
        return null;
    }

    public boolean isAccessTokenValid(String token, UserDetails userDetails) {
        return isTokenValid(token, userDetails, JwtTokenType.ACCESS);
    }

    public boolean isRefreshTokenValid(String token, UserDetails userDetails) {
        return isTokenValid(token, userDetails, JwtTokenType.REFRESH);
    }

    public boolean isRefreshToken(String token) {
        return JwtTokenType.REFRESH == extractTokenType(token);
    }

    private boolean isTokenValid(String token, UserDetails userDetails, JwtTokenType expectedType) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername())
                && expectedType == extractTokenType(token)
                && !isTokenExpired(token);
    }

    public boolean isTokenExpired(String token) {
        return extractClaims(token).getExpiration().before(new Date());
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
