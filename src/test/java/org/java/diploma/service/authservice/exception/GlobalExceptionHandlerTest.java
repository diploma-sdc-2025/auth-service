package org.java.diploma.service.authservice.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleMethodArgumentNotValid_returnsBadRequest() throws Exception {
        HttpServletRequest request = request("/api/auth/register");

        BeanPropertyBindingResult binding = new BeanPropertyBindingResult(new Object(), "register");
        binding.addError(new FieldError("register", "email", "must not be blank"));
        binding.addError(new FieldError("register", "password", null));

        Method method = GlobalExceptionHandlerTest.class.getDeclaredMethod("dummy", String.class);
        MethodParameter parameter = new MethodParameter(method, 0);
        MethodArgumentNotValidException exception = new MethodArgumentNotValidException(parameter, binding);

        ResponseEntity<?> response = handler.handleMethodArgumentNotValid(exception, request);

        assertStatusAndPath(response, HttpStatus.BAD_REQUEST, "/api/auth/register");
        ErrorResponse body = (ErrorResponse) response.getBody();
        assertNotNull(body);
        assertEquals("Validation failed", body.getError());
        assertTrue(body.getMessage().contains("email"));
        assertTrue(body.getMessage().contains("Invalid value"));
    }

    @Test
    void handleIllegalArgument_returnsBadRequest() {
        ResponseEntity<?> response = handler.handleIllegalArgument(
                new IllegalArgumentException("bad arg"),
                request("/api/auth/login")
        );
        assertStatusAndPath(response, HttpStatus.BAD_REQUEST, "/api/auth/login");
        assertEquals("Invalid request", ((ErrorResponse) response.getBody()).getError());
    }

    @Test
    void handleIllegalState_returnsConflict() {
        ResponseEntity<?> response = handler.handleIllegalState(
                new IllegalStateException("bad state"),
                request("/api/auth/refresh")
        );
        assertStatusAndPath(response, HttpStatus.CONFLICT, "/api/auth/refresh");
        assertEquals("Invalid state", ((ErrorResponse) response.getBody()).getError());
    }

    @Test
    void handleAuthException_returnsUnauthorized() {
        ResponseEntity<?> response = handler.handleAuthException(
                new AuthException("auth failed"),
                request("/api/auth/login")
        );
        assertStatusAndPath(response, HttpStatus.UNAUTHORIZED, "/api/auth/login");
        assertEquals("Authentication failed", ((ErrorResponse) response.getBody()).getError());
    }

    @Test
    void handleUserExists_returnsConflict() {
        ResponseEntity<?> response = handler.handleUserAlreadyExists(
                new UserAlreadyExistsException("exists"),
                request("/api/auth/register")
        );
        assertStatusAndPath(response, HttpStatus.CONFLICT, "/api/auth/register");
        assertEquals("User already exists", ((ErrorResponse) response.getBody()).getError());
    }

    @Test
    void handleInvalidToken_returnsUnauthorized() {
        ResponseEntity<?> response = handler.handleInvalidToken(
                new InvalidTokenException("invalid"),
                request("/api/auth/reset-password")
        );
        assertStatusAndPath(response, HttpStatus.UNAUTHORIZED, "/api/auth/reset-password");
        assertEquals("Invalid token", ((ErrorResponse) response.getBody()).getError());
    }

    @Test
    void handleUserInactive_returnsForbidden() {
        ResponseEntity<?> response = handler.handleUserInactive(
                new UserInactiveException("inactive"),
                request("/api/auth/login")
        );
        assertStatusAndPath(response, HttpStatus.FORBIDDEN, "/api/auth/login");
        assertEquals("User inactive", ((ErrorResponse) response.getBody()).getError());
    }

    @Test
    void handleGeneric_returnsInternalServerError() {
        ResponseEntity<?> response = handler.handleGeneric(
                new RuntimeException("boom"),
                request("/api/auth/unknown")
        );
        assertStatusAndPath(response, HttpStatus.INTERNAL_SERVER_ERROR, "/api/auth/unknown");
        ErrorResponse body = (ErrorResponse) response.getBody();
        assertEquals("Internal server error", body.getError());
        assertEquals("An unexpected error occurred", body.getMessage());
    }

    private static HttpServletRequest request(String path) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn(path);
        return request;
    }

    private static void assertStatusAndPath(ResponseEntity<?> response, HttpStatus status, String path) {
        assertEquals(status, response.getStatusCode());
        ErrorResponse body = (ErrorResponse) response.getBody();
        assertNotNull(body);
        assertEquals(status.value(), body.getStatus());
        assertEquals(path, body.getPath());
        assertNotNull(body.getTimestamp());
    }

    @SuppressWarnings("unused")
    private void dummy(String value) {
        // helper method for MethodParameter creation
    }
}
