package org.springsecurity.example.security.jwt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum JwtTokenType {
    ACCESS("access"),
    REFRESH("refresh");

    private final String claimValue;
}
