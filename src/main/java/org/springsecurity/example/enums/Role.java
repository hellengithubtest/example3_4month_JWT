package org.springsecurity.example.enums;

public enum Role {
    USER("ROLE_USER"),
    READ("users:read"),
    BLOCK("users:block");

    private final String authority;

    Role(String authority) {
        this.authority = authority;
    }

    public String getAuthority() {
        return authority;
    }
}
