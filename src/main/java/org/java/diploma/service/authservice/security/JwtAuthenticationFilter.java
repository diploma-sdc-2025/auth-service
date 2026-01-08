package org.java.diploma.service.authservice.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final int BEARER_PREFIX_LENGTH = 7;

    private static final String LOG_FILTER_INVOKED = "JWT authentication filter invoked for URI: {}";
    private static final String LOG_NO_TOKEN = "No authorization header or invalid Bearer token for URI: {}";
    private static final String LOG_TOKEN_VALID = "JWT token validated successfully for user ID: {}";
    private static final String LOG_AUTH_SET = "Authentication set in SecurityContext for user ID: {}";
    private static final String LOG_TOKEN_INVALID = "JWT token validation failed: {}";
    private static final String LOG_SECURITY_CLEARED = "SecurityContext cleared due to invalid token";

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        log.debug(LOG_FILTER_INVOKED, request.getRequestURI());

        String header = request.getHeader(HEADER_AUTHORIZATION);

        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            log.debug(LOG_NO_TOKEN, request.getRequestURI());
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String token = header.substring(BEARER_PREFIX_LENGTH);
            Claims claims = jwtService.parseAndValidate(token);

            String userId = claims.getSubject();
            log.debug(LOG_TOKEN_VALID, userId);

            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(
                            userId,
                            null,
                            Collections.emptyList()
                    );

            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(auth);
            log.debug(LOG_AUTH_SET, userId);

        } catch (Exception ex) {
            log.warn(LOG_TOKEN_INVALID, ex.getMessage());
            log.debug(LOG_SECURITY_CLEARED);
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}