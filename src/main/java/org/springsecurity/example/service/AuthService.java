package org.springsecurity.example.service;

import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springsecurity.example.dto.LoginRequest;
import org.springsecurity.example.dto.TokenResponse;
import org.springsecurity.example.model.RefreshTokenEntity;
import org.springsecurity.example.repository.RefreshTokenRepository;
import org.springsecurity.example.security.jwt.JwtService;

import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManager authManager;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshRepo;

    public TokenResponse login(LoginRequest req) {
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.username(), req.password())
        );
        UserDetails user = (UserDetails) auth.getPrincipal();
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        saveRefreshToken(user.getUsername(), refreshToken);
        return new TokenResponse(accessToken, refreshToken, jwtService.getAccessExpirationMs());
    }

    public TokenResponse refresh(String refreshToken) {
        try {
            if (!jwtService.isRefreshToken(refreshToken)) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Expected refresh token");
            }
        } catch (JwtException ignored) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
        }

        RefreshTokenEntity stored = refreshRepo.findByToken(refreshToken)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid refresh token"
                ));

        if (stored.isRevoked() || jwtService.isTokenExpired(refreshToken)) {
            refreshRepo.delete(stored);
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Refresh token expired or revoked"
            );
        }

        UserDetails user = userDetailsService.loadUserByUsername(stored.getUsername());
        if (!jwtService.isRefreshTokenValid(refreshToken, user)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
        }

        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        // Ротация: удаляем старый, сохраняем новый
        refreshRepo.delete(stored);
        saveRefreshToken(user.getUsername(), newRefreshToken);

        return new TokenResponse(newAccessToken, newRefreshToken, jwtService.getAccessExpirationMs());
    }

    private void saveRefreshToken(String username, String token) {
        RefreshTokenEntity entity = new RefreshTokenEntity();
        entity.setUsername(username);
        entity.setToken(token);
        entity.setExpiryDate(Instant.now().plus(Duration.ofDays(7)));
        refreshRepo.save(entity);
    }
}
