package org.springsecurity.example.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(description = "Запрос на обновление токенов")
public record RefreshRequest(
        @Schema(description = "JWT Refresh Token", example = "eyJhbGciOiJIUzI1NiJ9...")
        @NotBlank(message = "Refresh token is required")
        @Size(min = 20, max = 2000, message = "Invalid token format")
        String refreshToken
) {}
