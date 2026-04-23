package org.java.diploma.service.authservice.controller;

import org.java.diploma.service.authservice.entity.User;
import org.java.diploma.service.authservice.repository.UserRepository;
import org.java.diploma.service.authservice.security.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserController.class)
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
class UserControllerTest {

    @Autowired
    MockMvc mockMvc;

    @MockitoBean
    UserRepository userRepository;
    @MockitoBean
    JwtService jwtService;

    @Test
    void byIds_ok() throws Exception {
        User u1 = new User();
        u1.setId(1);
        u1.setUsername("alice");
        u1.setEmail("a@x.com");
        u1.setPasswordHash("x");

        User u2 = new User();
        u2.setId(2);
        u2.setUsername("bob");
        u2.setEmail("b@x.com");
        u2.setPasswordHash("y");

        when(userRepository.findAllById(any())).thenReturn(List.of(u1, u2));

        mockMvc.perform(get("/api/users/by-ids")
                        .param("ids", "1", "2")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(1))
                .andExpect(jsonPath("$[0].username").value("alice"))
                .andExpect(jsonPath("$[1].username").value("bob"));
    }

    @Test
    void byIds_empty() throws Exception {
        mockMvc.perform(get("/api/users/by-ids").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());
    }
}
