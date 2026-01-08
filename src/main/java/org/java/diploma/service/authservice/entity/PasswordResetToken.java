package org.java.diploma.service.authservice.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;

@Slf4j
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(
        name = "password_reset_tokens",
        indexes = {
                @Index(name = "idx_password_reset_token_hash", columnList = "token_hash"),
        }
)
public class PasswordResetToken {

    private static final String COLUMN_USER_ID = "user_id";
    private static final String COLUMN_TOKEN_HASH = "token_hash";
    private static final String COLUMN_EXPIRES_AT = "expires_at";
    private static final String COLUMN_CREATED_AT = "created_at";
    private static final String COLUMN_USED_AT = "used_at";

    private static final String LOG_TOKEN_CREATED = "Password reset token created for user ID: {}";
    private static final String LOG_TOKEN_USABILITY_CHECK = "Checking token usability - Used: {}, Expired: {}";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = COLUMN_USER_ID, nullable = false)
    private User user;

    @Column(name = COLUMN_TOKEN_HASH, nullable = false, unique = true)
    private String tokenHash;

    @Column(name = COLUMN_EXPIRES_AT, nullable = false)
    private Instant expiresAt;

    @Column(name = COLUMN_CREATED_AT, nullable = false)
    private Instant createdAt;

    @Column(name = COLUMN_USED_AT)
    private Instant usedAt;

    @PrePersist
    void onCreate() {
        this.createdAt = Instant.now();
        log.debug(LOG_TOKEN_CREATED, user != null ? user.getId() : null);
    }

    public boolean isUsable(Instant now) {
        boolean isUsed = usedAt != null;
        boolean isExpired = !expiresAt.isAfter(now);
        log.debug(LOG_TOKEN_USABILITY_CHECK, isUsed, isExpired);
        return !isUsed && !isExpired;
    }
}