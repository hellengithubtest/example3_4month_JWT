package org.springsecurity.example.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Безопасное представление пользователя без пароля и внутренних ролей")
public record UserSummaryResponse(
        Long id,
        String username,
        boolean enabled
) {
}
