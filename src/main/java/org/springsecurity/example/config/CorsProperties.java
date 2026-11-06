package org.springsecurity.example.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "app.security.cors")
public record CorsProperties(
        List<String> allowedOrigins,
        List<String> allowedMethods,
        List<String> allowedHeaders,
        Duration maxAge
) {
    public CorsProperties {
        allowedOrigins = requireExplicitValues(allowedOrigins, "allowed origins");
        allowedMethods = requireExplicitValues(allowedMethods, "allowed methods");
        allowedHeaders = requireExplicitValues(allowedHeaders, "allowed headers");
        if (maxAge == null || maxAge.isNegative()) {
            throw new IllegalStateException("CORS max age must not be negative");
        }
        allowedOrigins.forEach(CorsProperties::validateOrigin);
    }

    private static List<String> requireExplicitValues(List<String> values, String propertyName) {
        if (values == null || values.isEmpty() || values.stream()
                .anyMatch(value -> value == null || value.isBlank() || "*".equals(value))) {
            throw new IllegalStateException("CORS " + propertyName + " must be explicit and must not contain '*'");
        }
        return List.copyOf(values);
    }

    private static void validateOrigin(String origin) {
        URI uri;
        try {
            uri = URI.create(origin);
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("Invalid CORS origin: " + origin, exception);
        }
        if (!("http".equals(uri.getScheme()) || "https".equals(uri.getScheme()))
                || uri.getHost() == null
                || uri.getUserInfo() != null
                || (uri.getPath() != null && !uri.getPath().isEmpty())
                || uri.getQuery() != null
                || uri.getFragment() != null) {
            throw new IllegalStateException("CORS origin must contain only scheme, host and optional port: " + origin);
        }
    }
}
