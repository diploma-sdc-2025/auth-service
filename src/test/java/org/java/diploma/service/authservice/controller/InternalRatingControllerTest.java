package org.java.diploma.service.authservice.controller;

import org.java.diploma.service.authservice.dto.MatchRatingOutcomeRequest;
import org.java.diploma.service.authservice.security.JwtService;
import org.java.diploma.service.authservice.service.MatchRatingService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(value = InternalRatingController.class)
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
class InternalRatingControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private MatchRatingService matchRatingService;
    @MockitoBean
    private JwtService jwtService;

    @Test
    void getRatingReturnsValueFromService() throws Exception {
        when(matchRatingService.getRatingOrDefault(77L)).thenReturn(1444);

        mockMvc.perform(get("/api/internal/users/77/rating")
                        .header("X-Internal-Secret", "secret"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rating").value(1444));

        verify(matchRatingService).assertSecret("secret");
    }

    @Test
    void postMatchRatingReturnsNoContentForValidBody() throws Exception {
        mockMvc.perform(post("/api/internal/match-rating")
                        .header("X-Internal-Secret", "secret")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"winnerUserId":10,"loserUserId":20}
                                """))
                .andExpect(status().isNoContent());

        verify(matchRatingService).assertSecret("secret");
        verify(matchRatingService).applyMatchOutcome(10L, 20L);
    }

    @Test
    void postMatchRatingRejectsSameWinnerAndLoser() throws Exception {
        mockMvc.perform(post("/api/internal/match-rating")
                        .header("X-Internal-Secret", "secret")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"winnerUserId":10,"loserUserId":10}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void postMatchRatingRejectsValidationErrors() throws Exception {
        mockMvc.perform(post("/api/internal/match-rating")
                        .header("X-Internal-Secret", "secret")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {}
                                """))
                .andExpect(status().isBadRequest());
    }
}
