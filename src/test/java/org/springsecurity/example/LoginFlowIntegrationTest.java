package org.springsecurity.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springsecurity.example.dto.LoginRequest;
import org.springsecurity.example.dto.TokenResponse;
import org.springsecurity.example.enums.Role;
import org.springsecurity.example.model.UserEntity;
import org.springsecurity.example.repository.RefreshTokenRepository;
import org.springsecurity.example.repository.UsersRepository;
import org.springsecurity.example.security.jwt.JwtService;
import org.springsecurity.example.service.UsersDetailsService;

import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class LoginFlowIntegrationTest {

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
        assertSeededUser("user2", Set.of(Role.USER));
        assertSeededUser("admin", Set.of(Role.ADMIN));
    }

    @Test
    void userAndAdminCanLoginAndReceiveValidTokens() throws Exception {
        assertSuccessfulLogin("user1", "ROLE_USER");
        assertSuccessfulLogin("admin", "ROLE_ADMIN");
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

    private void assertSuccessfulLogin(String username, String expectedAuthority) throws Exception {
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

        TokenResponse tokens = objectMapper.readValue(
                result.getResponse().getContentAsByteArray(),
                TokenResponse.class
        );
        UserDetails userDetails = usersDetailsService.loadUserByUsername(username);

        assertEquals(username, jwtService.extractUsername(tokens.accessToken()));
        assertTrue(jwtService.isTokenValid(tokens.accessToken(), userDetails));
        assertTrue(jwtService.isTokenValid(tokens.refreshToken(), userDetails));
        assertTrue(refreshTokenRepository.findByToken(tokens.refreshToken()).isPresent());
        assertTrue(userDetails.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals(expectedAuthority)));
    }
}
