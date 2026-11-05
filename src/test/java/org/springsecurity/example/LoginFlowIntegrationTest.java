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
import org.springsecurity.example.dto.LoginRequest;
import org.springsecurity.example.dto.RefreshRequest;
import org.springsecurity.example.dto.TokenResponse;
import org.springsecurity.example.enums.Role;
import org.springsecurity.example.model.UserEntity;
import org.springsecurity.example.repository.RefreshTokenRepository;
import org.springsecurity.example.repository.UsersRepository;
import org.springsecurity.example.security.jwt.JwtService;
import org.springsecurity.example.security.jwt.JwtTokenType;
import org.springsecurity.example.service.UsersDetailsService;

import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
        assertFalse(refreshTokenRepository.findByToken(tokens.refreshToken()).isPresent());
        assertTrue(refreshTokenRepository.findByToken(rotatedTokens.refreshToken()).isPresent());
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
        assertTrue(refreshTokenRepository.findByToken(tokens.refreshToken()).isPresent());
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
}
