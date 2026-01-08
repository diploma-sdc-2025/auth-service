package org.java.diploma.service.authservice.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.java.diploma.service.authservice.dto.*;
import org.java.diploma.service.authservice.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@Tag(name = "Authentication", description = "Authentication and token management")
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    // Swagger operation summaries
    private static final String OP_REGISTER = "Register user";
    private static final String OP_LOGIN = "User login";
    private static final String OP_REFRESH = "Refresh tokens";
    private static final String OP_LOGOUT = "Logout";
    private static final String OP_FORGOT = "Forgot password";
    private static final String OP_RESET = "Reset password";

    // Swagger descriptions
    private static final String LOGIN_DESCRIPTION = "Authenticates a user and returns JWT tokens.";

    // Log messages
    private static final String LOG_REGISTER_REQUEST = "Registration request received for email: {}";
    private static final String LOG_REGISTER_SUCCESS = "User registered successfully: {}";
    private static final String LOG_LOGIN_REQUEST = "Login request received for email: {}";
    private static final String LOG_LOGIN_SUCCESS = "User logged in successfully: {}";
    private static final String LOG_REFRESH_REQUEST = "Token refresh request received";
    private static final String LOG_REFRESH_SUCCESS = "Tokens refreshed successfully";
    private static final String LOG_LOGOUT_REQUEST = "Logout request received";
    private static final String LOG_LOGOUT_SUCCESS = "User logged out successfully";
    private static final String LOG_FORGOT_REQUEST = "Forgot password request received for email: {}";
    private static final String LOG_FORGOT_SUCCESS = "Password reset token created for email: {}";
    private static final String LOG_RESET_REQUEST = "Password reset request received";
    private static final String LOG_RESET_SUCCESS = "Password reset successfully";

    private final AuthService auth;

    public AuthController(AuthService auth) {
        this.auth = auth;
    }

    @Operation(summary = OP_REGISTER)
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
        log.info(LOG_REGISTER_REQUEST, req.email());
        auth.register(req);
        log.info(LOG_REGISTER_SUCCESS, req.email());
        return ResponseEntity.ok().build();
    }

    @Operation(summary = OP_LOGIN, description = LOGIN_DESCRIPTION)
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest req) {
        log.info(LOG_LOGIN_REQUEST, req.identifier());
        AuthResponse response = auth.login(req);
        log.info(LOG_LOGIN_SUCCESS, req.identifier());
        return ResponseEntity.ok(response);
    }

    @Operation(summary = OP_REFRESH)
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest req) {
        log.info(LOG_REFRESH_REQUEST);
        AuthResponse response = auth.refresh(req);
        log.info(LOG_REFRESH_SUCCESS);
        return ResponseEntity.ok(response);
    }

    @Operation(summary = OP_LOGOUT)
    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@RequestBody RefreshRequest req) {
        log.info(LOG_LOGOUT_REQUEST);
        auth.logout(req.refreshToken());
        log.info(LOG_LOGOUT_SUCCESS);
    }

    @Operation(summary = OP_FORGOT)
    @PostMapping("/password/forgot")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void forgot(@Valid @RequestBody ForgotPasswordRequest req) {
        log.info(LOG_FORGOT_REQUEST, req.email());
        auth.createPasswordResetToken(req);
        log.info(LOG_FORGOT_SUCCESS, req.email());
    }

    @Operation(summary = OP_RESET)
    @PostMapping("/password/reset")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void reset(@Valid @RequestBody ResetPasswordRequest req) {
        log.info(LOG_RESET_REQUEST);
        auth.resetPassword(req);
        log.info(LOG_RESET_SUCCESS);
    }
}