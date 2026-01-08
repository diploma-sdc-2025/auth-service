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
        name = "user_session",
        indexes = {
                @Index(name = "idx_user_sessions_user_id", columnList = "user_id"),
                @Index(name = "idx_user_sessions_refresh_token_id", columnList = "refresh_token_id")
        }
)
public class UserSession {

    private static final String COLUMN_USER_ID = "user_id";
    private static final String COLUMN_REFRESH_TOKEN_ID = "refresh_token_id";
    private static final String COLUMN_DEVICE_INFO = "device_info";
    private static final String COLUMN_STARTED_AT = "started_at";
    private static final String COLUMN_LAST_ACTIVITY_AT = "last_activity_at";
    private static final String COLUMN_ENDED_AT = "ended_at";

    private static final String LOG_SESSION_CREATED = "User session created - User ID: {}, device: {}";
    private static final String LOG_SESSION_ACTIVITY_CHECK = "Checking session activity - Active: {}";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = COLUMN_USER_ID, nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = COLUMN_REFRESH_TOKEN_ID)
    private RefreshToken refreshToken;

    @Column(name = COLUMN_DEVICE_INFO)
    private String deviceInfo;

    @Column(name = COLUMN_STARTED_AT, nullable = false)
    private Instant startedAt;

    @Column(name = COLUMN_LAST_ACTIVITY_AT, nullable = false)
    private Instant lastActivityAt;

    @Column(name = COLUMN_ENDED_AT)
    private Instant endedAt;

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        this.startedAt = now;
        this.lastActivityAt = now;
        log.info(LOG_SESSION_CREATED, user != null ? user.getId() : null, deviceInfo);
    }

    public boolean isActive() {
        boolean active = endedAt == null;
        log.debug(LOG_SESSION_ACTIVITY_CHECK, active);
        return active;
    }
}