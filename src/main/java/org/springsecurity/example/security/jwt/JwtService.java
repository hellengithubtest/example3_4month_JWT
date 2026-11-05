package org.springsecurity.example.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springsecurity.example.config.JwtProperties;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtService {
    private static final int MIN_SECRET_BYTES = 32;
    private static final String TOKEN_TYPE_CLAIM = "token_type";

    private final SecretKey signingKey;

    private final Duration accessExpiration;
    private final Duration refreshExpiration;

    public JwtService(JwtProperties properties) {
        this.signingKey = createSigningKey(properties.secret());
        this.accessExpiration = properties.accessTokenExpiration();
        this.refreshExpiration = properties.refreshTokenExpiration();
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
        return buildToken(userDetails, accessExpiration, JwtTokenType.ACCESS);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(userDetails, refreshExpiration, JwtTokenType.REFRESH);
    }

    private String buildToken(UserDetails userDetails, Duration expiration, JwtTokenType tokenType) {
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(userDetails.getUsername())
                .claim(TOKEN_TYPE_CLAIM, tokenType.getClaimValue())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration.toMillis()))
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

    public long getAccessExpirationMs() {
        return accessExpiration.toMillis();
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
