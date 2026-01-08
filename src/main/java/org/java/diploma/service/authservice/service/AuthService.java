package org.java.diploma.service.authservice.service;

import lombok.extern.slf4j.Slf4j;
import org.java.diploma.service.authservice.dto.*;
import org.java.diploma.service.authservice.entity.PasswordResetToken;
import org.java.diploma.service.authservice.entity.RefreshToken;
import org.java.diploma.service.authservice.entity.User;
import org.java.diploma.service.authservice.entity.UserSession;
import org.java.diploma.service.authservice.exception.AuthException;
import org.java.diploma.service.authservice.exception.InvalidTokenException;
import org.java.diploma.service.authservice.exception.UserAlreadyExistsException;
import org.java.diploma.service.authservice.exception.UserInactiveException;
import org.java.diploma.service.authservice.repository.PasswordResetTokenRepository;
import org.java.diploma.service.authservice.repository.RefreshTokenRepository;
import org.java.diploma.service.authservice.repository.UserRepository;
import org.java.diploma.service.authservice.repository.UserSessionRepository;
import org.java.diploma.service.authservice.security.JwtService;
import org.java.diploma.service.authservice.util.TokenUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

@Slf4j
@Service
public class AuthService {

    // Error messages
    private static final String ERROR_EMAIL_IN_USE = "Email already in use";
    private static final String ERROR_USERNAME_IN_USE = "Username already in use";
    private static final String ERROR_INVALID_CREDENTIALS = "Invalid credentials";
    private static final String ERROR_USER_INACTIVE = "User inactive";
    private static final String ERROR_INVALID_REFRESH_TOKEN = "Invalid refresh token";
    private static final String ERROR_REFRESH_TOKEN_EXPIRED = "Refresh token expired/revoked";
    private static final String ERROR_INVALID_RESET_TOKEN = "Invalid token";
    private static final String ERROR_RESET_TOKEN_EXPIRED = "Token expired/used";

    // Log messages
    private static final String LOG_REGISTER_START = "Registration attempt for email: {}, username: {}";
    private static final String LOG_REGISTER_EMAIL_EXISTS = "Registration failed - email already exists: {}";
    private static final String LOG_REGISTER_USERNAME_EXISTS = "Registration failed - username already exists: {}";
    private static final String LOG_REGISTER_SUCCESS = "User registered successfully - ID: {}, username: {}";

    private static final String LOG_LOGIN_START = "Login attempt for identifier: {}";
    private static final String LOG_LOGIN_USER_NOT_FOUND = "Login failed - user not found for identifier: {}";
    private static final String LOG_LOGIN_USER_INACTIVE = "Login failed - user inactive: {}";
    private static final String LOG_LOGIN_INVALID_PASSWORD = "Login failed - invalid password for user: {}";
    private static final String LOG_LOGIN_SUCCESS = "User logged in successfully - ID: {}, username: {}";
    private static final String LOG_LOGIN_REFRESH_TOKEN_CREATED = "Refresh token created for user ID: {}";
    private static final String LOG_LOGIN_SESSION_CREATED = "User session created for user ID: {}";

    private static final String LOG_REFRESH_START = "Token refresh attempt";
    private static final String LOG_REFRESH_TOKEN_NOT_FOUND = "Refresh failed - token not found";
    private static final String LOG_REFRESH_TOKEN_INACTIVE = "Refresh failed - token inactive or expired";
    private static final String LOG_REFRESH_USER_INACTIVE = "Refresh failed - user inactive: {}";
    private static final String LOG_REFRESH_OLD_TOKEN_REVOKED = "Old refresh token revoked for user ID: {}";
    private static final String LOG_REFRESH_NEW_TOKEN_CREATED = "New refresh token created for user ID: {}";
    private static final String LOG_REFRESH_SUCCESS = "Token refreshed successfully for user ID: {}";

    private static final String LOG_LOGOUT_START = "Logout attempt";
    private static final String LOG_LOGOUT_TOKEN_NOT_FOUND = "Logout - refresh token not found";
    private static final String LOG_LOGOUT_SUCCESS = "User logged out - refresh token revoked";

    private static final String LOG_FORGOT_PASSWORD_START = "Password reset token request for email: {}";
    private static final String LOG_FORGOT_PASSWORD_USER_NOT_FOUND = "Password reset - user not found for email: {}";
    private static final String LOG_FORGOT_PASSWORD_TOKEN_CREATED = "Password reset token created for user ID: {}";

    private static final String LOG_RESET_PASSWORD_START = "Password reset attempt";
    private static final String LOG_RESET_PASSWORD_TOKEN_NOT_FOUND = "Password reset failed - token not found";
    private static final String LOG_RESET_PASSWORD_TOKEN_INVALID = "Password reset failed - token expired or used";
    private static final String LOG_RESET_PASSWORD_SUCCESS = "Password reset successfully for user ID: {}";

    private static final String LOG_RESOLVE_USER_EMAIL = "Resolving user by email: {}";
    private static final String LOG_RESOLVE_USER_USERNAME = "Resolving user by username: {}";

    // Special characters
    private static final String EMAIL_INDICATOR = "@";

    private final UserRepository users;
    private final RefreshTokenRepository refreshTokens;
    private final UserSessionRepository sessions;
    private final PasswordResetTokenRepository resetTokens;
    private final PasswordEncoder encoder;
    private final JwtService jwt;

    private final Duration refreshTtl = Duration.ofDays(30);
    private final Duration resetTtl = Duration.ofMinutes(30);

    public AuthService(
            UserRepository users,
            RefreshTokenRepository refreshTokens,
            UserSessionRepository sessions,
            PasswordResetTokenRepository resetTokens,
            PasswordEncoder encoder,
            JwtService jwt
    ) {
        this.users = users;
        this.refreshTokens = refreshTokens;
        this.sessions = sessions;
        this.resetTokens = resetTokens;
        this.encoder = encoder;
        this.jwt = jwt;
    }

    @Transactional
    public void register(RegisterRequest req) {
        log.info(LOG_REGISTER_START, req.email(), req.username());

        users.findByEmailIgnoreCase(req.email()).ifPresent(u -> {
            log.warn(LOG_REGISTER_EMAIL_EXISTS, req.email());
            throw new UserAlreadyExistsException(ERROR_EMAIL_IN_USE);
        });

        users.findByUsernameIgnoreCase(req.username()).ifPresent(u -> {
            log.warn(LOG_REGISTER_USERNAME_EXISTS, req.username());
            throw new UserAlreadyExistsException(ERROR_USERNAME_IN_USE);
        });

        User u = new User();
        u.setEmail(req.email().trim().toLowerCase());
        u.setUsername(req.username().trim());
        u.setPasswordHash(encoder.encode(req.password()));
        users.save(u);

        log.info(LOG_REGISTER_SUCCESS, u.getId(), u.getUsername());
    }

    @Transactional
    public AuthResponse login(LoginRequest req) {
        log.info(LOG_LOGIN_START, req.identifier());

        User user = resolveUser(req.identifier())
                .orElseThrow(() -> {
                    log.warn(LOG_LOGIN_USER_NOT_FOUND, req.identifier());
                    return new AuthException(ERROR_INVALID_CREDENTIALS);
                });

        if (!user.isActive()) {
            log.warn(LOG_LOGIN_USER_INACTIVE, user.getId());
            throw new UserInactiveException(ERROR_USER_INACTIVE);
        }

        if (!encoder.matches(req.password(), user.getPasswordHash())) {
            log.warn(LOG_LOGIN_INVALID_PASSWORD, user.getId());
            throw new AuthException(ERROR_INVALID_CREDENTIALS);
        }

        user.setLastLoginAt(Instant.now());

        String refreshRaw = TokenUtil.newOpaqueToken();
        String refreshHash = TokenUtil.sha256B64Url(refreshRaw);

        RefreshToken rt = new RefreshToken();
        rt.setUser(user);
        rt.setTokenHash(refreshHash);
        rt.setExpiresAt(Instant.now().plus(refreshTtl));
        rt.setDeviceInfo(req.deviceInfo());
        refreshTokens.save(rt);
        log.debug(LOG_LOGIN_REFRESH_TOKEN_CREATED, user.getId());

        UserSession session = new UserSession();
        session.setUser(user);
        session.setRefreshToken(rt);
        session.setDeviceInfo(req.deviceInfo());
        sessions.save(session);
        log.debug(LOG_LOGIN_SESSION_CREATED, user.getId());

        String access = jwt.createAccessToken(user.getId(), user.getUsername());
        log.info(LOG_LOGIN_SUCCESS, user.getId(), user.getUsername());

        return new AuthResponse(access, refreshRaw);
    }

    @Transactional
    public AuthResponse refresh(RefreshRequest req) {
        log.info(LOG_REFRESH_START);

        Instant now = Instant.now();
        String oldHash = TokenUtil.sha256B64Url(req.refreshToken());

        RefreshToken old = refreshTokens.findByTokenHash(oldHash)
                .orElseThrow(() -> {
                    log.warn(LOG_REFRESH_TOKEN_NOT_FOUND);
                    return new InvalidTokenException(ERROR_INVALID_REFRESH_TOKEN);
                });

        if (!old.isActive(now)) {
            log.warn(LOG_REFRESH_TOKEN_INACTIVE);
            throw new InvalidTokenException(ERROR_REFRESH_TOKEN_EXPIRED);
        }

        User user = old.getUser();
        if (!user.isActive()) {
            log.warn(LOG_REFRESH_USER_INACTIVE, user.getId());
            throw new UserInactiveException(ERROR_USER_INACTIVE);
        }

        old.setRevokedAt(now);
        log.debug(LOG_REFRESH_OLD_TOKEN_REVOKED, user.getId());

        String newRaw = TokenUtil.newOpaqueToken();
        String newHash = TokenUtil.sha256B64Url(newRaw);

        RefreshToken next = new RefreshToken();
        next.setUser(user);
        next.setTokenHash(newHash);
        next.setExpiresAt(now.plus(refreshTtl));
        next.setDeviceInfo(req.deviceInfo());
        refreshTokens.save(next);
        log.debug(LOG_REFRESH_NEW_TOKEN_CREATED, user.getId());

        old.setReplacedBy(next.getId());
        refreshTokens.save(old);

        UserSession session = new UserSession();
        session.setUser(user);
        session.setRefreshToken(next);
        session.setDeviceInfo(req.deviceInfo());
        sessions.save(session);

        String access = jwt.createAccessToken(user.getId(), user.getUsername());
        log.info(LOG_REFRESH_SUCCESS, user.getId());

        return new AuthResponse(access, newRaw);
    }

    @Transactional
    public void logout(String refreshTokenRaw) {
        log.info(LOG_LOGOUT_START);

        String hash = TokenUtil.sha256B64Url(refreshTokenRaw);
        Optional<RefreshToken> tokenOpt = refreshTokens.findByTokenHash(hash);

        if (tokenOpt.isEmpty()) {
            log.debug(LOG_LOGOUT_TOKEN_NOT_FOUND);
            return;
        }

        RefreshToken rt = tokenOpt.get();
        rt.setRevokedAt(Instant.now());
        refreshTokens.save(rt);
        log.info(LOG_LOGOUT_SUCCESS);
    }

    @Transactional
    public void createPasswordResetToken(ForgotPasswordRequest req) {
        log.info(LOG_FORGOT_PASSWORD_START, req.email());

        Optional<User> userOpt = users.findByEmailIgnoreCase(req.email().trim());
        if (userOpt.isEmpty()) {
            log.debug(LOG_FORGOT_PASSWORD_USER_NOT_FOUND, req.email());
            return;
        }

        String raw = TokenUtil.newOpaqueToken();
        PasswordResetToken prt = new PasswordResetToken();
        prt.setUser(userOpt.get());
        prt.setTokenHash(TokenUtil.sha256B64Url(raw));
        prt.setExpiresAt(Instant.now().plus(resetTtl));
        resetTokens.save(prt);

        log.info(LOG_FORGOT_PASSWORD_TOKEN_CREATED, userOpt.get().getId());

        // TODO - send the token to the email
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest req) {
        log.info(LOG_RESET_PASSWORD_START);

        Instant now = Instant.now();
        String hash = TokenUtil.sha256B64Url(req.token());

        PasswordResetToken token = resetTokens.findByTokenHash(hash)
                .orElseThrow(() -> {
                    log.warn(LOG_RESET_PASSWORD_TOKEN_NOT_FOUND);
                    return new InvalidTokenException(ERROR_INVALID_RESET_TOKEN);
                });

        if (!token.isUsable(now)) {
            log.warn(LOG_RESET_PASSWORD_TOKEN_INVALID);
            throw new InvalidTokenException(ERROR_RESET_TOKEN_EXPIRED);
        }

        User user = token.getUser();
        user.setPasswordHash(encoder.encode(req.newPassword()));
        users.save(user);

        token.setUsedAt(now);
        resetTokens.save(token);

        log.info(LOG_RESET_PASSWORD_SUCCESS, user.getId());

        // TODO - revoke all refresh tokens for this user
        // refreshTokens.findAllByUser_Id(user.getId()).forEach(rt -> { rt.setRevokedAt(now); });
    }

    private Optional<User> resolveUser(String identifier) {
        String id = identifier.trim();
        if (id.contains(EMAIL_INDICATOR)) {
            log.debug(LOG_RESOLVE_USER_EMAIL, id);
            return users.findByEmailIgnoreCase(id);
        }
        log.debug(LOG_RESOLVE_USER_USERNAME, id);
        return users.findByUsernameIgnoreCase(id);
    }
}