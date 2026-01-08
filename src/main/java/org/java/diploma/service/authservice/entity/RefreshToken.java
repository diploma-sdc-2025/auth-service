package org.java.diploma.service.authservice.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(
        name = "refresh_tokens",
        indexes = {
                @Index(name = "idx_refresh_tokens_user_id", columnList = "user_id"),
                @Index(name = "idx_refresh_tokens_token_hash", columnList = "token_hash"),
                @Index(name = "idx_refresh_tokens_expires_at", columnList = "expires_at")
        }
)
public class RefreshToken {

    private static final String COLUMN_USER_ID = "user_id";
    private static final String COLUMN_TOKEN_HASH = "token_hash";
    private static final String COLUMN_EXPIRES_AT = "expires_at";
    private static final String COLUMN_CREATED_AT = "created_at";
    private static final String COLUMN_REVOKED_AT = "revoked_at";
    private static final String COLUMN_REPLACED_BY = "replaced_by";
    private static final String COLUMN_DEVICE_INFO = "device_info";

    private static final String LOG_TOKEN_CREATED = "Refresh token created for user ID: {}, device: {}";
    private static final String LOG_TOKEN_ACTIVITY_CHECK = "Checking token activity - Revoked: {}, Expired: {}";

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

    @Column(name = COLUMN_REVOKED_AT)
    private Instant revokedAt;

    @Column(name = COLUMN_REPLACED_BY)
    private Integer replacedBy;

    @Column(name = COLUMN_DEVICE_INFO)
    private String deviceInfo;

    @PrePersist
    void onCreate() {
        this.createdAt = Instant.now();
        log.debug(LOG_TOKEN_CREATED, user != null ? user.getId() : null, deviceInfo);
    }

    public boolean isActive(Instant now) {
        boolean isRevoked = revokedAt != null;
        boolean isExpired = !expiresAt.isAfter(now);
        log.debug(LOG_TOKEN_ACTIVITY_CHECK, isRevoked, isExpired);
        return !isRevoked && !isExpired;
    }
}