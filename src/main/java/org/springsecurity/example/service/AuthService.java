package org.springsecurity.example.service;

import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springsecurity.example.config.JwtProperties;
import org.springsecurity.example.dto.LoginRequest;
import org.springsecurity.example.dto.TokenResponse;
import org.springsecurity.example.model.RefreshTokenEntity;
import org.springsecurity.example.repository.RefreshTokenRepository;
import org.springsecurity.example.security.jwt.JwtService;
import org.springsecurity.example.security.jwt.JwtFailureCategory;
import org.springsecurity.example.security.jwt.RefreshTokenHasher;

import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final AuthenticationManager authManager;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final RefreshTokenHasher refreshTokenHasher;
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

    @Transactional
    public TokenResponse refresh(String refreshToken) {
        try {
            if (!jwtService.isRefreshToken(refreshToken)) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Expected refresh token");
            }
        } catch (JwtException | IllegalArgumentException exception) {
            logJwtRefreshFailure(exception);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
        }

        String tokenHash = refreshTokenHasher.hash(refreshToken);
        RefreshTokenEntity stored = refreshRepo.findByTokenHashForUpdate(tokenHash)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid refresh token"
                ));

        if (stored.isRevoked() || !stored.getExpiryDate().isAfter(Instant.now())) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Refresh token expired or revoked"
            );
        }

        UserDetails user = userDetailsService.loadUserByUsername(stored.getUsername());
        try {
            if (!user.isEnabled() || !jwtService.isRefreshTokenValid(refreshToken, user)) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
            }
        } catch (JwtException | IllegalArgumentException exception) {
            logJwtRefreshFailure(exception);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
        }

        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        stored.setRevoked(true);
        saveRefreshToken(user.getUsername(), newRefreshToken);

        return new TokenResponse(newAccessToken, newRefreshToken, jwtService.getAccessExpirationMs());
    }

    @Transactional
    public void logout(String refreshToken) {
        String tokenHash = refreshTokenHasher.hash(refreshToken);
        refreshRepo.findByTokenHashForUpdate(tokenHash)
                .ifPresent(stored -> stored.setRevoked(true));
    }

    @Transactional
    public void revokeAll(String username) {
        refreshRepo.revokeAllByUsername(username);
    }

    private void logJwtRefreshFailure(RuntimeException exception) {
        log.warn(
                "JWT refresh rejected: category={}, operation=refresh",
                JwtFailureCategory.from(exception)
        );
    }

    private void saveRefreshToken(String username, String token) {
        RefreshTokenEntity entity = new RefreshTokenEntity();
        entity.setUsername(username);
        entity.setTokenHash(refreshTokenHasher.hash(token));
        entity.setExpiryDate(Instant.now().plus(jwtProperties.refreshTokenExpiration()));
        refreshRepo.save(entity);
    }
}
