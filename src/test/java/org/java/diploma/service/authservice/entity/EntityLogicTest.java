package org.java.diploma.service.authservice.entity;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.time.Instant;

class EntityLogicTest {

    @Test
    void refreshToken_isActive() {
        RefreshToken rt = new RefreshToken();
        rt.setExpiresAt(Instant.now().plusSeconds(60));

        assertTrue(rt.isActive(Instant.now()));
    }

    @Test
    void passwordResetToken_notUsableWhenExpired() {
        PasswordResetToken prt = new PasswordResetToken();
        prt.setExpiresAt(Instant.now().minusSeconds(10));

        assertFalse(prt.isUsable(Instant.now()));
    }

    @Test
    void refreshToken_notActiveWhenRevokedOrExpired() {
        RefreshToken revoked = new RefreshToken();
        revoked.setExpiresAt(Instant.now().plusSeconds(60));
        revoked.setRevokedAt(Instant.now());
        assertFalse(revoked.isActive(Instant.now()));

        RefreshToken expired = new RefreshToken();
        expired.setExpiresAt(Instant.now().minusSeconds(1));
        assertFalse(expired.isActive(Instant.now()));
    }

    @Test
    void passwordResetToken_notUsableWhenUsed() {
        PasswordResetToken used = new PasswordResetToken();
        used.setExpiresAt(Instant.now().plusSeconds(60));
        used.setUsedAt(Instant.now());

        assertFalse(used.isUsable(Instant.now()));
    }

    @Test
    void userSession_onCreateSetsTimestampsAndActiveState() {
        UserSession session = new UserSession();
        session.onCreate();

        assertNotNull(session.getStartedAt());
        assertNotNull(session.getLastActivityAt());
        assertTrue(session.isActive());

        session.setEndedAt(Instant.now());
        assertFalse(session.isActive());
    }
}

