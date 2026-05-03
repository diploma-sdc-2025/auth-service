package org.java.diploma.service.authservice.controller;

import io.swagger.v3.oas.annotations.Hidden;
import jakarta.validation.Valid;
import org.java.diploma.service.authservice.dto.MatchRatingOutcomeRequest;
import org.java.diploma.service.authservice.service.MatchRatingService;
import org.java.diploma.service.authservice.dto.RatingValueResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Hidden
@RestController
@RequestMapping("/api/internal")
public class InternalRatingController {

    private final MatchRatingService matchRatingService;

    public InternalRatingController(MatchRatingService matchRatingService) {
        this.matchRatingService = matchRatingService;
    }

    @GetMapping("/users/{userId}/rating")
    public RatingValueResponse getRating(
            @RequestHeader("X-Internal-Secret") String secret,
            @PathVariable long userId
    ) {
        matchRatingService.assertSecret(secret);
        return new RatingValueResponse(matchRatingService.getRatingOrDefault(userId));
    }

    @PostMapping("/match-rating")
    public ResponseEntity<Void> recordMatchRating(
            @RequestHeader("X-Internal-Secret") String secret,
            @Valid @RequestBody MatchRatingOutcomeRequest body
    ) {
        if (body.winnerUserId() == body.loserUserId()) {
            throw new IllegalArgumentException("winner and loser must differ");
        }
        matchRatingService.assertSecret(secret);
        matchRatingService.applyMatchOutcome(body.winnerUserId(), body.loserUserId());
        return ResponseEntity.noContent().build();
    }

}
