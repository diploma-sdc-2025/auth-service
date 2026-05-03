package org.java.diploma.service.authservice.service;

import lombok.extern.slf4j.Slf4j;
import org.java.diploma.service.authservice.entity.User;
import org.java.diploma.service.authservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@Service
public class MatchRatingService {

    private static final int DELTA = 10;

    private final UserRepository users;
    private final String internalSecret;

    public MatchRatingService(
            UserRepository users,
            @Value("${diploma.internal-api.secret:local-dev-internal-secret}") String internalSecret
    ) {
        this.users = users;
        this.internalSecret = internalSecret;
    }

    public void assertSecret(String provided) {
        if (internalSecret == null || internalSecret.isBlank()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Internal API not configured");
        }
        if (provided == null || !internalSecret.equals(provided)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid internal credentials");
        }
    }

    /** Applies static ±10 for registered users only. Guest accounts ({@code Guest-*} usernames) are skipped. */
    @Transactional
    public void applyMatchOutcome(long winnerUserId, long loserUserId) {
        applyForUser(winnerUserId, DELTA);
        applyForUser(loserUserId, -DELTA);
    }

    private void applyForUser(long userId, int delta) {
        if (userId <= 0) {
            return;
        }
        users.findById((int) userId).ifPresent(u -> {
            if (isGuest(u)) {
                return;
            }
            int rating = u.getRating();
            int next = rating + delta;
            if (next < 0) {
                next = 0;
            }
            u.setRating(next);
            users.save(u);
            log.debug("Rating update userId={} delta={} {} -> {}", userId, delta, rating, next);
        });
    }

    private static boolean isGuest(User u) {
        String n = u.getUsername();
        return n != null && n.startsWith("Guest-");
    }

    /** Current rating for analytics / leaderboards (defaults to 1000 if user missing). */
    @Transactional(readOnly = true)
    public int getRatingOrDefault(long userId) {
        if (userId <= 0) {
            return 1000;
        }
        return users.findById((int) userId).map(User::getRating).orElse(1000);
    }
}
