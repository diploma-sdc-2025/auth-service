package org.java.diploma.service.authservice.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
@Configuration
public class AuthBeansConfig {

    private static final String LOG_PASSWORD_ENCODER_CREATED = "BCryptPasswordEncoder bean created successfully";

    @Bean
    public PasswordEncoder passwordEncoder() {
        log.info(LOG_PASSWORD_ENCODER_CREATED);
        return new BCryptPasswordEncoder();
    }
}