package org.java.diploma.service.authservice.dto;

import jakarta.validation.constraints.Positive;

public record MatchRatingOutcomeRequest(
        @Positive long winnerUserId,
        @Positive long loserUserId
) {
}
