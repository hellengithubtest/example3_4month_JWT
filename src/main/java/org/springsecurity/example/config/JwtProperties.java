package org.springsecurity.example.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.Objects;

@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
        String secret,
        Duration accessTokenExpiration,
        Duration refreshTokenExpiration
) {
    public JwtProperties {
        Objects.requireNonNull(secret, "JWT secret is required");
        validatePositive(accessTokenExpiration, "Access token expiration");
        validatePositive(refreshTokenExpiration, "Refresh token expiration");
    }

    private static void validatePositive(Duration duration, String propertyName) {
        if (duration == null || duration.isZero() || duration.isNegative()) {
            throw new IllegalStateException(propertyName + " must be positive");
        }
    }
}
