package org.springsecurity.example.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springsecurity.example.enums.Role;

@Getter
@Setter
@Entity
@Table(name = "roles")
public class RoleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Храним БЕЗ префикса "ROLE_", например: "USER", "ADMIN", "MANAGER"
    @Column(unique = true, nullable = false, length = 50)
    @Enumerated(EnumType.STRING)
    private Role name;
}
