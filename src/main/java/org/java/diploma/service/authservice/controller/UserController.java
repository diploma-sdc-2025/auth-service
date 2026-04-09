package org.java.diploma.service.authservice.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.java.diploma.service.authservice.dto.UserPublicResponse;
import org.java.diploma.service.authservice.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Slf4j
@Tag(name = "Users", description = "Public user metadata for clients")
@RestController
@RequestMapping("/api/users")
public class UserController {

    private static final int MAX_IDS = 100;

    private static final String LOG_BY_IDS = "Resolved {} usernames for {} id(s)";

    private final UserRepository users;

    public UserController(UserRepository users) {
        this.users = users;
    }

    @Operation(summary = "Resolve usernames by user ids (JWT required)")
    @GetMapping("/by-ids")
    public List<UserPublicResponse> byIds(@RequestParam(value = "ids", required = false) List<Integer> ids) {
        if (ids == null || ids.isEmpty()) {
            return List.of();
        }
        Set<Integer> distinct = new LinkedHashSet<>();
        for (Integer id : ids) {
            if (id != null) {
                distinct.add(id);
            }
        }
        if (distinct.size() > MAX_IDS) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At most " + MAX_IDS + " ids allowed");
        }
        List<UserPublicResponse> out = new ArrayList<>();
        users.findAllById(distinct).forEach(u -> out.add(new UserPublicResponse(u.getId(), u.getUsername())));
        log.debug(LOG_BY_IDS, out.size(), distinct.size());
        return out;
    }
}
