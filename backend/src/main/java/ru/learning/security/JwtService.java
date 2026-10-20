package ru.learning.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
    private final SecretKey secretKey;
    private final long expirationMinutes;

    public JwtService(
            SecretKey secretKey,
            @Value("${app.jwt.expiration-minutes:30}") long expirationMinutes) {
        this.secretKey = secretKey;
        this.expirationMinutes = expirationMinutes;
    }

    public String generateToken(UserDetails user) {
        Instant now = Instant.now();
        List<String> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        return Jwts.builder()
                .subject(user.getUsername())
                .claim("roles", roles)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(expirationMinutes * 60)))
                .signWith(secretKey)
                .compact();
    }

    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    public List<String> extractRoles(String token) {
        Object claim = parseClaims(token).get("roles");
        if (!(claim instanceof List<?> values)
                || values.stream().anyMatch(role -> !(role instanceof String))) {
            throw new io.jsonwebtoken.JwtException("В JWT отсутствует список ролей");
        }
        return values.stream().map(String.class::cast).toList();
    }

    public boolean isValid(String token, String username) {
        Claims claims = parseClaims(token);
        return username.equals(claims.getSubject())
                && claims.getExpiration() != null
                && claims.getExpiration().after(new Date());
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
