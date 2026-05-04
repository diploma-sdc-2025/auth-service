package org.java.diploma.service.authservice.security;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


@SpringBootTest(
        classes = JwtService.class,
        properties = {
                "auth.jwt.secret=12345678901234567890123456789012",
                "spring.flyway.enabled=false",
                "spring.jpa.hibernate.ddl-auto=none"
        }
)
class JwtServiceTest {

    @Autowired
    JwtService jwtService;

    @Test
    void createAndParseToken() {
        String token = jwtService.createAccessToken(1, "user");

        Claims claims = jwtService.parseAndValidate(token);

        assertEquals("1", claims.getSubject());
        assertEquals("user", claims.get("username"));
        assertFalse(Boolean.TRUE.equals(claims.get("guest")));
    }

    @Test
    void createAndParseGuestToken() {
        String token = jwtService.createAccessToken(7, "Guest-7", true);

        Claims claims = jwtService.parseAndValidate(token);

        assertEquals("7", claims.getSubject());
        assertEquals("Guest-7", claims.get("username"));
        assertTrue(Boolean.TRUE.equals(claims.get("guest")));
    }

    @Test
    void parseThrowsForInvalidJwt() {
        assertThrows(Exception.class, () -> jwtService.parseAndValidate("not-a-jwt"));
    }

    @Test
    void initRejectsTooShortSecret() {
        JwtService shortSecret = new JwtService("too-short", 900, "issuer");
        assertThrows(IllegalArgumentException.class, shortSecret::init);
    }
}

