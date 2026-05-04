package org.java.diploma.service.authservice.service;

import org.java.diploma.service.authservice.entity.User;
import org.java.diploma.service.authservice.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MatchRatingServiceTest {

    @Mock
    private UserRepository users;

    private MatchRatingService service;

    @BeforeEach
    void setUp() {
        service = new MatchRatingService(users, "secret");
    }

    @Test
    void assertSecretRejectsMissingOrInvalidSecret() {
        MatchRatingService missing = new MatchRatingService(users, " ");

        assertThatThrownBy(() -> missing.assertSecret("x"))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));

        assertThatThrownBy(() -> service.assertSecret("bad"))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN));
    }

    @Test
    void assertSecretAcceptsCorrectValue() {
        service.assertSecret("secret");
    }

    @Test
    void applyMatchOutcomeUpdatesRegisteredUsersAndClampsLoserRatingAtZero() {
        User winner = new User();
        winner.setId(1);
        winner.setUsername("kon");
        winner.setRating(1200);
        User loser = new User();
        loser.setId(2);
        loser.setUsername("other");
        loser.setRating(5);
        when(users.findById(1)).thenReturn(Optional.of(winner));
        when(users.findById(2)).thenReturn(Optional.of(loser));

        service.applyMatchOutcome(1L, 2L);

        assertThat(winner.getRating()).isEqualTo(1210);
        assertThat(loser.getRating()).isZero();
        verify(users).save(winner);
        verify(users).save(loser);
    }

    @Test
    void applyMatchOutcomeSkipsGuestAndInvalidUserIds() {
        User guest = new User();
        guest.setId(3);
        guest.setUsername("Guest-123");
        guest.setRating(1000);
        when(users.findById(3)).thenReturn(Optional.of(guest));

        service.applyMatchOutcome(3L, -1L);

        verify(users, never()).save(guest);
    }

    @Test
    void getRatingOrDefaultReturnsStoredRatingOrDefault() {
        User user = new User();
        user.setId(7);
        user.setRating(1337);
        when(users.findById(7)).thenReturn(Optional.of(user));
        when(users.findById(9)).thenReturn(Optional.empty());

        assertThat(service.getRatingOrDefault(7L)).isEqualTo(1337);
        assertThat(service.getRatingOrDefault(9L)).isEqualTo(1000);
        assertThat(service.getRatingOrDefault(0L)).isEqualTo(1000);
    }
}
