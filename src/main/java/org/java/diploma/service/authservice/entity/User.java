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
        name = "users",
        indexes = {
                @Index(name = "idx_users_username", columnList = "username"),
                @Index(name = "idx_users_email", columnList = "email")
        }
)
public class User {

    private static final String COLUMN_PASSWORD_HASH = "password_hash";
    private static final String COLUMN_IS_ACTIVE = "is_active";
    private static final String COLUMN_IS_VERIFIED = "is_verified";
    private static final String COLUMN_CREATED_AT = "created_at";
    private static final String COLUMN_UPDATED_AT = "updated_at";
    private static final String COLUMN_LAST_LOGIN_AT = "last_login_at";

    private static final String LOG_USER_CREATED = "User created - ID: {}, username: {}, email: {}";
    private static final String LOG_USER_UPDATED = "User updated - ID: {}, username: {}";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false, length = 50, unique = true)
    private String username;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(name = COLUMN_PASSWORD_HASH, nullable = false)
    private String passwordHash;

    @Column(name = COLUMN_IS_ACTIVE, nullable = false)
    private boolean active = true;

    @Column(name = COLUMN_IS_VERIFIED, nullable = false)
    private boolean verified = false;

    @Column(name = COLUMN_CREATED_AT, nullable = false)
    private Instant createdAt;

    @Column(name = COLUMN_UPDATED_AT, nullable = false)
    private Instant updatedAt;

    @Column(name = COLUMN_LAST_LOGIN_AT)
    private Instant lastLoginAt;

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
        log.info(LOG_USER_CREATED, id, username, email);
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = Instant.now();
        log.debug(LOG_USER_UPDATED, id, username);
    }
}