package org.java.diploma.service.authservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

@Slf4j
@Service
public class JwtService {

    private static final int MIN_SECRET_LENGTH = 32;
    private static final String CLAIM_USERNAME = "username";

    private static final String PROPERTY_JWT_SECRET = "${auth.jwt.secret}";
    private static final String PROPERTY_ACCESS_TTL = "${auth.jwt.access-ttl-seconds:900}";
    private static final String PROPERTY_ISSUER = "${auth.jwt.issuer:yourgame-auth}";

    private static final String ERROR_SECRET_TOO_SHORT = "JWT secret must be at least 32 characters";

    private static final String LOG_JWT_INIT = "JwtService initialized - Issuer: {}, Access TTL: {} seconds";
    private static final String LOG_SECRET_LENGTH_CHECK = "JWT secret length validated: {} characters";
    private static final String LOG_TOKEN_CREATED = "Access token created for user ID: {}, username: {}";
    private static final String LOG_TOKEN_PARSED = "JWT token parsed and validated successfully";
    private static final String LOG_TOKEN_PARSE_FAILED = "JWT token parsing failed: {}";

    private final String secret;
    private final long accessTtlSeconds;
    private final String issuer;

    private SecretKey key;

    public JwtService(
            @Value(PROPERTY_JWT_SECRET) String secret,
            @Value(PROPERTY_ACCESS_TTL) long accessTtlSeconds,
            @Value(PROPERTY_ISSUER) String issuer
    ) {
        this.secret = secret;
        this.accessTtlSeconds = accessTtlSeconds;
        this.issuer = issuer;
    }

    @PostConstruct
    void init() {
        log.debug(LOG_SECRET_LENGTH_CHECK, secret.length());

        if (secret.length() < MIN_SECRET_LENGTH) {
            log.error(ERROR_SECRET_TOO_SHORT);
            throw new IllegalArgumentException(ERROR_SECRET_TOO_SHORT);
        }

        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        log.info(LOG_JWT_INIT, issuer, accessTtlSeconds);
    }

    public String createAccessToken(Integer userId, String username) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(accessTtlSeconds);

        String token = Jwts.builder()
                .issuer(issuer)
                .subject(String.valueOf(userId))
                .claim(CLAIM_USERNAME, username)
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .signWith(key)
                .compact();

        log.debug(LOG_TOKEN_CREATED, userId, username);
        return token;
    }

    public Claims parseAndValidate(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            log.debug(LOG_TOKEN_PARSED);
            return claims;
        } catch (Exception ex) {
            log.debug(LOG_TOKEN_PARSE_FAILED, ex.getMessage());
            throw ex;
        }
    }
}