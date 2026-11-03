package org.springsecurity.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import org.springsecurity.example.dto.LoginRequest;
import org.springsecurity.example.dto.TokenResponse;
import org.springsecurity.example.repository.UsersRepository;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class UserManagementIntegrationTest extends JwtIntegrationTestSupport {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UsersRepository usersRepository;

    @Test
    void readerCanReadOtherUsersButCannotBlockThem() throws Exception {
        String accessToken = login("reader");

        mockMvc.perform(get("/api/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[*].username",
                        containsInAnyOrder("user1", "moderator")))
                .andExpect(jsonPath("$[*].password").doesNotExist());

        mockMvc.perform(post("/api/users/3001/block")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessToken)))
                .andExpect(status().isForbidden());

        assertTrue(usersRepository.findById(3001L).orElseThrow().isEnabled());
    }

    @Test
    void userWithoutReadPermissionCannotReadOtherUsers() throws Exception {
        String accessToken = login("user1");

        mockMvc.perform(get("/api/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessToken)))
                .andExpect(status().isForbidden());
    }

    @Test
    void moderatorCanReadAndBlockAnotherUser() throws Exception {
        String readerAccessToken = login("reader");
        String accessToken = login("moderator");

        mockMvc.perform(get("/api/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessToken)))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/users/3002/block")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(3002))
                .andExpect(jsonPath("$.username").value("reader"))
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.password").doesNotExist());

        assertFalse(usersRepository.findById(3002L).orElseThrow().isEnabled());

        mockMvc.perform(get("/api/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(readerAccessToken)))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("reader", "password")
                        )))
                .andExpect(status().isForbidden());
    }

    @Test
    void moderatorCannotBlockOwnAccount() throws Exception {
        String accessToken = login("moderator");

        mockMvc.perform(post("/api/users/3003/block")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessToken)))
                .andExpect(status().isBadRequest());

        assertTrue(usersRepository.findById(3003L).orElseThrow().isEnabled());
    }

    private String login(String username) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest(username, "password")
                        )))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readValue(
                result.getResponse().getContentAsByteArray(),
                TokenResponse.class
        ).accessToken();
    }

    private String bearer(String accessToken) {
        return "Bearer " + accessToken;
    }
}
