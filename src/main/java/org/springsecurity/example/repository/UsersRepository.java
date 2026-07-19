package org.springsecurity.example.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springsecurity.example.model.UserEntity;

import java.util.Optional;

public interface UsersRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByUsername(String username);
}
