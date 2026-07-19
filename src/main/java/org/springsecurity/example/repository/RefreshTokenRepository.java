package org.springsecurity.example.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springsecurity.example.model.RefreshTokenEntity;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {
    Optional<RefreshTokenEntity> findByToken(String token);
    List<RefreshTokenEntity> findByUsername(String username);
    void deleteByUsername(String username);
}
