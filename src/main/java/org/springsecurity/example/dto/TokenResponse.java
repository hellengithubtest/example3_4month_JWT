package org.springsecurity.example.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Ответ с токенами")
public record TokenResponse(
        @Schema(description = "Короткоживущий Access Token")
        String accessToken,

        @Schema(description = "Долгоживущий Refresh Token")
        String refreshToken,

        @Schema(description = "Тип токена", example = "Bearer")
        String tokenType,    // всегда "Bearer"

        @Schema(description = "Время жизни Access Token в секундах", example = "900")
        Long expiresIn       // TTL access-токена в секундах (удобно для фронтенда)
) {
    // Удобный конструктор для создания из сервисного слоя
    public TokenResponse(String accessToken, String refreshToken, long accessExpirationMs) {
        this(accessToken, refreshToken, "Bearer", accessExpirationMs / 1000);
    }
}
