package org.springsecurity.example.security.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public enum JwtFailureCategory {
    EXPIRED,
    INVALID_SIGNATURE,
    MALFORMED,
    UNSUPPORTED,
    SUBJECT_NOT_FOUND,
    INVALID_FORMAT,
    INVALID;

    public static JwtFailureCategory from(RuntimeException exception) {
        if (exception instanceof ExpiredJwtException) {
            return EXPIRED;
        }
        if (exception instanceof SignatureException) {
            return INVALID_SIGNATURE;
        }
        if (exception instanceof MalformedJwtException) {
            return MALFORMED;
        }
        if (exception instanceof UnsupportedJwtException) {
            return UNSUPPORTED;
        }
        if (exception instanceof UsernameNotFoundException) {
            return SUBJECT_NOT_FOUND;
        }
        if (exception instanceof IllegalArgumentException) {
            return INVALID_FORMAT;
        }
        return INVALID;
    }
}
