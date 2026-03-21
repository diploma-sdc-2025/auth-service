package org.java.diploma.service.authservice.config;

import lombok.extern.slf4j.Slf4j;
import org.java.diploma.service.authservice.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
@Configuration
public class SecurityConfig {

    private static final String AUTH_API_PATTERN = "/api/auth/**";
    private static final String ACTUATOR_PATTERN = "/actuator/**";
    private static final String OPENAPI_DOCS_PATTERN = "/v3/api-docs/**";
    private static final String SWAGGER_UI_PATTERN = "/swagger-ui/**";
    private static final String SWAGGER_UI_HTML = "/swagger-ui.html";

    private static final String LOG_CONFIGURING_SECURITY = "Configuring security filter chain";
    private static final String LOG_CSRF_DISABLED = "CSRF protection disabled for stateless API";
    private static final String LOG_SESSION_STATELESS = "Session management set to STATELESS";
    private static final String LOG_PUBLIC_ENDPOINTS = "Configured public endpoints: {}, {}, {}, {}, {}";
    private static final String LOG_JWT_FILTER_ADDED = "JWT authentication filter added before UsernamePasswordAuthenticationFilter";
    private static final String LOG_SECURITY_CONFIGURED = "Security filter chain configured successfully";

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthenticationFilter jwtAuthenticationFilter
    ) throws Exception {

        log.info(LOG_CONFIGURING_SECURITY);

        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> {
                    csrf.disable();
                    log.debug(LOG_CSRF_DISABLED);
                })
                .sessionManagement(sm -> {
                    sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                    log.debug(LOG_SESSION_STATELESS);
                })
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(
                                    AUTH_API_PATTERN,
                                    ACTUATOR_PATTERN,
                                    OPENAPI_DOCS_PATTERN,
                                    SWAGGER_UI_PATTERN,
                                    SWAGGER_UI_HTML
                            ).permitAll()
                            .anyRequest().authenticated();
                    log.debug(LOG_PUBLIC_ENDPOINTS,
                            AUTH_API_PATTERN, ACTUATOR_PATTERN, OPENAPI_DOCS_PATTERN,
                            SWAGGER_UI_PATTERN, SWAGGER_UI_HTML);
                })
                .addFilterBefore(
                        jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class
                );

        log.debug(LOG_JWT_FILTER_ADDED);
        log.info(LOG_SECURITY_CONFIGURED);

        return http.build();
    }
}