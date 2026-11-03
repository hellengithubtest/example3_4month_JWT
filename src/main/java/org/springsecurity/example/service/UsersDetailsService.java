package org.springsecurity.example.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springsecurity.example.model.UserEntity;
import org.springsecurity.example.repository.UsersRepository;

import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UsersDetailsService implements UserDetailsService {
    private final UsersRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        var authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().getAuthority()))
                .collect(Collectors.toList());

        // Возвращаем стандартный Spring UserDetails
        return new User(
                user.getUsername(),
                user.getPassword(),
                user.isEnabled(),
                true, true, true,
                authorities
        );
    }
}
