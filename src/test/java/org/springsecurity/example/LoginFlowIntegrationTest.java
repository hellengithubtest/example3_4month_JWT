package org.springsecurity.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springsecurity.example.config.JwtProperties;
import org.springsecurity.example.dto.LoginRequest;
import org.springsecurity.example.dto.RefreshRequest;
import org.springsecurity.example.dto.TokenResponse;
import org.springsecurity.example.enums.Role;
import org.springsecurity.example.model.RefreshTokenEntity;
import org.springsecurity.example.model.UserEntity;
import org.springsecurity.example.repository.RefreshTokenRepository;
import org.springsecurity.example.repository.UsersRepository;
import org.springsecurity.example.security.jwt.JwtService;
import org.springsecurity.example.security.jwt.JwtTokenType;
import org.springsecurity.example.security.jwt.RefreshTokenHasher;
import org.springsecurity.example.service.UsersDetailsService;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class LoginFlowIntegrationTest extends JwtIntegrationTestSupport {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UsersRepository usersRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UsersDetailsService usersDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private RefreshTokenHasher refreshTokenHasher;

    @Autowired
    private JwtProperties jwtProperties;

    @Test
    void dataSqlCreatesKnownUsersWithRolesAndWorkingPassword() {
        assertSeededUser("user1", Set.of(Role.USER));
        assertSeededUser("reader", Set.of(Role.READ));
        assertSeededUser("moderator", Set.of(Role.READ, Role.BLOCK));
    }

    @Test
    void allUsersCanLoginAndReceiveValidTokensWithExpectedAuthorities() throws Exception {
        assertSuccessfulLogin("user1", Set.of("ROLE_USER"));
        assertSuccessfulLogin("reader", Set.of("users:read"));
        assertSuccessfulLogin("moderator", Set.of("users:read", "users:block"));
    }

    @Test
    void invalidLoginRequestReturnsBadRequest() throws Exception {
        LoginRequest invalidRequest = new LoginRequest("ab", "short");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(result -> assertInstanceOf(
                        MethodArgumentNotValidException.class,
                        result.getResolvedException()
                ));
    }

    @Test
    void invalidRefreshRequestReturnsBadRequest() throws Exception {
        RefreshRequest invalidRequest = new RefreshRequest("short");

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(result -> assertInstanceOf(
                        MethodArgumentNotValidException.class,
                        result.getResolvedException()
                ));
    }

    @Test
    void accessAndRefreshTokensCannotBeUsedInterchangeably() throws Exception {
        TokenResponse tokens = login("reader");
        assertEquals(JwtTokenType.ACCESS, jwtService.extractTokenType(tokens.accessToken()));
        assertEquals(JwtTokenType.REFRESH, jwtService.extractTokenType(tokens.refreshToken()));

        mockMvc.perform(get("/api/users")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokens.refreshToken()))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new RefreshRequest(tokens.accessToken())
                        )))
                .andExpect(status().isUnauthorized());

        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new RefreshRequest(tokens.refreshToken())
                        )))
                .andExpect(status().isOk())
                .andReturn();

        TokenResponse rotatedTokens = objectMapper.readValue(
                refreshResult.getResponse().getContentAsByteArray(),
                TokenResponse.class
        );
        assertEquals(JwtTokenType.ACCESS, jwtService.extractTokenType(rotatedTokens.accessToken()));
        assertEquals(JwtTokenType.REFRESH, jwtService.extractTokenType(rotatedTokens.refreshToken()));
        assertTrue(storedToken(tokens.refreshToken()).isRevoked());
        assertFalse(storedToken(rotatedTokens.refreshToken()).isRevoked());

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new RefreshRequest(tokens.refreshToken())
                        )))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void databaseStoresOnlyRefreshTokenHash() throws Exception {
        Instant beforeLogin = Instant.now();
        TokenResponse tokens = login("user1");
        Instant afterLogin = Instant.now();
        String expectedHash = refreshTokenHasher.hash(tokens.refreshToken());

        RefreshTokenEntity stored = refreshTokenRepository.findByTokenHash(expectedHash).orElseThrow();
        assertEquals(64, stored.getTokenHash().length());
        assertEquals(expectedHash, stored.getTokenHash());
        assertFalse(stored.getTokenHash().equals(tokens.refreshToken()));
        assertFalse(refreshTokenRepository.findByTokenHash(tokens.refreshToken()).isPresent());
        assertTrue(stored.getExpiryDate().isAfter(
                beforeLogin.plus(jwtProperties.refreshTokenExpiration()).minusSeconds(1)
        ));
        assertTrue(stored.getExpiryDate().isBefore(
                afterLogin.plus(jwtProperties.refreshTokenExpiration()).plusSeconds(1)
        ));
    }

    @Test
    void logoutRevokesOnlyPresentedRefreshToken() throws Exception {
        TokenResponse firstSession = login("user1");
        TokenResponse secondSession = login("user1");

        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new RefreshRequest(firstSession.refreshToken())
                        )))
                .andExpect(status().isNoContent());

        assertTrue(storedToken(firstSession.refreshToken()).isRevoked());
        assertFalse(storedToken(secondSession.refreshToken()).isRevoked());

        assertRefreshRejected(firstSession.refreshToken());
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new RefreshRequest(secondSession.refreshToken())
                        )))
                .andExpect(status().isOk());
    }

    @Test
    void revokeAllRequiresAccessTokenAndRevokesEverySession() throws Exception {
        TokenResponse firstSession = login("reader");
        TokenResponse secondSession = login("reader");

        mockMvc.perform(post("/api/auth/revoke-all"))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/auth/revoke-all")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + firstSession.accessToken()))
                .andExpect(status().isNoContent());

        assertTrue(refreshTokenRepository.findByUsername("reader").stream()
                .allMatch(RefreshTokenEntity::isRevoked));
        assertRefreshRejected(firstSession.refreshToken());
        assertRefreshRejected(secondSession.refreshToken());
    }

    @Test
    void concurrentRefreshRotatesTokenOnlyOnce() throws Exception {
        TokenResponse tokens = login("moderator");
        String requestBody = objectMapper.writeValueAsString(
                new RefreshRequest(tokens.refreshToken())
        );
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);

        try {
            Future<Integer> first = executor.submit(() -> performRefreshAfter(start, requestBody));
            Future<Integer> second = executor.submit(() -> performRefreshAfter(start, requestBody));
            start.countDown();

            List<Integer> statuses = List.of(first.get(), second.get()).stream()
                    .sorted()
                    .toList();
            assertEquals(List.of(200, 401), statuses);
        } finally {
            executor.shutdownNow();
        }
    }

    private void assertSeededUser(String username, Set<Role> expectedRoles) {
        UserEntity user = usersRepository.findByUsername(username).orElseThrow();
        Set<Role> actualRoles = user.getRoles().stream()
                .map(role -> role.getName())
                .collect(Collectors.toSet());

        assertEquals(expectedRoles, actualRoles);
        assertTrue(user.isEnabled());
        assertTrue(passwordEncoder.matches("password", user.getPassword()));
    }

    private void assertSuccessfulLogin(String username, Set<String> expectedAuthorities) throws Exception {
        TokenResponse tokens = login(username);
        UserDetails userDetails = usersDetailsService.loadUserByUsername(username);

        assertEquals(username, jwtService.extractUsername(tokens.accessToken()));
        assertEquals(JwtTokenType.ACCESS, jwtService.extractTokenType(tokens.accessToken()));
        assertEquals(JwtTokenType.REFRESH, jwtService.extractTokenType(tokens.refreshToken()));
        assertTrue(jwtService.isAccessTokenValid(tokens.accessToken(), userDetails));
        assertTrue(jwtService.isRefreshTokenValid(tokens.refreshToken(), userDetails));
        assertFalse(storedToken(tokens.refreshToken()).isRevoked());
        Set<String> actualAuthorities = userDetails.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .collect(Collectors.toSet());
        assertEquals(expectedAuthorities, actualAuthorities);
    }

    private TokenResponse login(String username) throws Exception {
        LoginRequest loginRequest = new LoginRequest(username, "password");

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andReturn();

        return objectMapper.readValue(
                result.getResponse().getContentAsByteArray(),
                TokenResponse.class
        );
    }

    private RefreshTokenEntity storedToken(String rawRefreshToken) {
        return refreshTokenRepository.findByTokenHash(refreshTokenHasher.hash(rawRefreshToken))
                .orElseThrow();
    }

    private void assertRefreshRejected(String refreshToken) throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new RefreshRequest(refreshToken)
                        )))
                .andExpect(status().isUnauthorized());
    }

    private int performRefreshAfter(CountDownLatch start, String requestBody) throws Exception {
        start.await();
        return mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andReturn()
                .getResponse()
                .getStatus();
    }
}
