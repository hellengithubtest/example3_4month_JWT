package org.springsecurity.example;

import org.junit.jupiter.api.Test;
import org.springsecurity.example.config.JwtProperties;
import org.springsecurity.example.security.jwt.JwtService;

import java.time.Duration;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtServiceConfigurationTest {

    private static final Duration ACCESS_EXPIRATION = Duration.ofMinutes(15);
    private static final Duration REFRESH_EXPIRATION = Duration.ofDays(7);

    @Test
    void acceptsBase64SecretWithAtLeast256Bits() {
        String validSecret = Base64.getEncoder().encodeToString(new byte[32]);

        assertDoesNotThrow(() -> createJwtService(validSecret));
    }

    @Test
    void rejectsSecretThatIsNotBase64() {
        assertThrows(IllegalStateException.class, () -> createJwtService("not-a-base64-secret"));
    }

    @Test
    void rejectsSecretShorterThan256Bits() {
        String weakSecret = Base64.getEncoder().encodeToString(new byte[31]);

        assertThrows(IllegalStateException.class, () -> createJwtService(weakSecret));
    }

    private JwtService createJwtService(String secret) {
        return new JwtService(new JwtProperties(
                secret,
                ACCESS_EXPIRATION,
                REFRESH_EXPIRATION
        ));
    }
}
