package org.springsecurity.example.service;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springsecurity.example.dto.UserSummaryResponse;
import org.springsecurity.example.model.UserEntity;
import org.springsecurity.example.repository.UsersRepository;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserManagementService {

    private final UsersRepository usersRepository;

    @Transactional(readOnly = true)
    public List<UserSummaryResponse> getOtherUsers(String currentUsername) {
        return usersRepository.findAll().stream()
                .filter(user -> !user.getUsername().equals(currentUsername))
                .map(this::toResponse)
                .toList();
    }

    @Transactional
    public UserSummaryResponse blockUser(long userId, String currentUsername) {
        UserEntity user = usersRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "User not found"
                ));

        if (user.getUsername().equals(currentUsername)) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "A user cannot block their own account"
            );
        }

        user.setEnabled(false);
        return toResponse(usersRepository.save(user));
    }

    private UserSummaryResponse toResponse(UserEntity user) {
        return new UserSummaryResponse(user.getId(), user.getUsername(), user.isEnabled());
    }
}
