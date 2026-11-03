package org.springsecurity.example.rest;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springsecurity.example.dto.UserSummaryResponse;
import org.springsecurity.example.service.UserManagementService;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@Tag(name = "User management", description = "Чтение и блокировка других пользователей")
@RequiredArgsConstructor
public class UsersRestController {

    private final UserManagementService userManagementService;

    @GetMapping
    @Operation(summary = "Получить других пользователей", description = "Требуется authority users:read")
    public List<UserSummaryResponse> getOtherUsers(Authentication authentication) {
        return userManagementService.getOtherUsers(authentication.getName());
    }

    @PostMapping("/{id}/block")
    @Operation(summary = "Заблокировать пользователя", description = "Требуется authority users:block")
    public ResponseEntity<UserSummaryResponse> blockUser(
            @PathVariable("id") long userId,
            Authentication authentication
    ) {
        return ResponseEntity.ok(
                userManagementService.blockUser(userId, authentication.getName())
        );
    }
}
