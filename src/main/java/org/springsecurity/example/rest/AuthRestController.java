package org.springsecurity.example.rest;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springsecurity.example.dto.LoginRequest;
import org.springsecurity.example.dto.RefreshRequest;
import org.springsecurity.example.dto.TokenResponse;
import org.springsecurity.example.service.AuthService;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Login, Logout & Token Refresh")
@RequiredArgsConstructor
public class AuthRestController {
    private final AuthService authService;

    @PostMapping("/login")
    @Operation(summary = "Авторизация пользователя", description = "Возвращает пару Access + Refresh токенов")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Успешный вход"),
            @ApiResponse(responseCode = "401", description = "Неверный логин или пароль"),
            @ApiResponse(responseCode = "400", description = "Ошибка валидации")
    })
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    @Operation(summary = "Обновление токенов", description = "Ротирует refresh token и возвращает новую пару токенов")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Токены успешно обновлены"),
            @ApiResponse(responseCode = "401", description = "Refresh token невалиден, истёк или отозван"),
            @ApiResponse(responseCode = "400", description = "Ошибка валидации")
    })
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return ResponseEntity.ok(authService.refresh(request.refreshToken()));
    }

    @PostMapping("/logout")
    @Operation(summary = "Выход", description = "Отзывает переданный refresh token")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Refresh token отозван"),
            @ApiResponse(responseCode = "400", description = "Ошибка валидации")
    })
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshRequest request) {
        authService.logout(request.refreshToken());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/revoke-all")
    @Operation(summary = "Отозвать все refresh token", description = "Требует действующий access token")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Все refresh token пользователя отозваны"),
            @ApiResponse(responseCode = "403", description = "Действующий access token отсутствует")
    })
    public ResponseEntity<Void> revokeAll(Authentication authentication) {
        authService.revokeAll(authentication.getName());
        return ResponseEntity.noContent().build();
    }
}
