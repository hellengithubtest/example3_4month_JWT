package org.springsecurity.example;

import org.junit.jupiter.api.Test;
import org.springsecurity.example.security.jwt.JwtService;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtServiceConfigurationTest {

    private static final long ACCESS_EXPIRATION_MS = 900_000;
    private static final long REFRESH_EXPIRATION_MS = 604_800_000;

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
        return new JwtService(secret, ACCESS_EXPIRATION_MS, REFRESH_EXPIRATION_MS);
    }
}
