package org.java.diploma.service.authservice.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    // Error messages
    private static final String ERROR_VALIDATION_FAILED = "Validation failed";
    private static final String ERROR_INVALID_REQUEST = "Invalid request";
    private static final String ERROR_INVALID_STATE = "Invalid state";
    private static final String ERROR_INTERNAL_SERVER = "Internal server error";
    private static final String ERROR_UNEXPECTED = "An unexpected error occurred";
    private static final String ERROR_INVALID_VALUE = "Invalid value";
    private static final String ERROR_AUTHENTICATION_FAILED = "Authentication failed";
    private static final String ERROR_USER_EXISTS = "User already exists";
    private static final String ERROR_INVALID_TOKEN = "Invalid token";
    private static final String ERROR_USER_INACTIVE = "User inactive";

    // Log messages
    private static final String LOG_VALIDATION_ERROR = "Validation error at {}: {}";
    private static final String LOG_ILLEGAL_ARGUMENT = "Illegal argument at {}: {}";
    private static final String LOG_ILLEGAL_STATE = "Illegal state at {}: {}";
    private static final String LOG_INTERNAL_ERROR = "Internal server error at {}: {}";
    private static final String LOG_AUTH_EXCEPTION = "Authentication exception at {}: {}";
    private static final String LOG_USER_EXISTS = "User already exists at {}: {}";
    private static final String LOG_INVALID_TOKEN = "Invalid token at {}: {}";
    private static final String LOG_USER_INACTIVE = "User inactive at {}: {}";

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpServletRequest request) {

        Map<String, String> errors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .collect(Collectors.toMap(
                        FieldError::getField,
                        error -> error.getDefaultMessage() != null ? error.getDefaultMessage() : ERROR_INVALID_VALUE,
                        (a, b) -> a
                ));

        log.warn(LOG_VALIDATION_ERROR, request.getRequestURI(), errors);

        return buildResponse(
                HttpStatus.BAD_REQUEST,
                ERROR_VALIDATION_FAILED,
                errors.toString(),
                request.getRequestURI()
        );
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<?> handleIllegalArgument(
            IllegalArgumentException ex,
            HttpServletRequest request) {

        log.warn(LOG_ILLEGAL_ARGUMENT, request.getRequestURI(), ex.getMessage());

        return buildResponse(
                HttpStatus.BAD_REQUEST,
                ERROR_INVALID_REQUEST,
                ex.getMessage(),
                request.getRequestURI()
        );
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<?> handleIllegalState(
            IllegalStateException ex,
            HttpServletRequest request) {

        log.warn(LOG_ILLEGAL_STATE, request.getRequestURI(), ex.getMessage());

        return buildResponse(
                HttpStatus.CONFLICT,
                ERROR_INVALID_STATE,
                ex.getMessage(),
                request.getRequestURI()
        );
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<?> handleAuthException(
            AuthException ex,
            HttpServletRequest request) {

        log.warn(LOG_AUTH_EXCEPTION, request.getRequestURI(), ex.getMessage());

        return buildResponse(
                HttpStatus.UNAUTHORIZED,
                ERROR_AUTHENTICATION_FAILED,
                ex.getMessage(),
                request.getRequestURI()
        );
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<?> handleUserAlreadyExists(
            UserAlreadyExistsException ex,
            HttpServletRequest request) {

        log.warn(LOG_USER_EXISTS, request.getRequestURI(), ex.getMessage());

        return buildResponse(
                HttpStatus.CONFLICT,
                ERROR_USER_EXISTS,
                ex.getMessage(),
                request.getRequestURI()
        );
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<?> handleInvalidToken(
            InvalidTokenException ex,
            HttpServletRequest request) {

        log.warn(LOG_INVALID_TOKEN, request.getRequestURI(), ex.getMessage());

        return buildResponse(
                HttpStatus.UNAUTHORIZED,
                ERROR_INVALID_TOKEN,
                ex.getMessage(),
                request.getRequestURI()
        );
    }

    @ExceptionHandler(UserInactiveException.class)
    public ResponseEntity<?> handleUserInactive(
            UserInactiveException ex,
            HttpServletRequest request) {

        log.warn(LOG_USER_INACTIVE, request.getRequestURI(), ex.getMessage());

        return buildResponse(
                HttpStatus.FORBIDDEN,
                ERROR_USER_INACTIVE,
                ex.getMessage(),
                request.getRequestURI()
        );
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGeneric(
            Exception ex,
            HttpServletRequest request) {

        log.error(LOG_INTERNAL_ERROR, request.getRequestURI(), ex.getMessage(), ex);

        return buildResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                ERROR_INTERNAL_SERVER,
                ERROR_UNEXPECTED,
                request.getRequestURI()
        );
    }

    private ResponseEntity<ErrorResponse> buildResponse(
            HttpStatus status,
            String error,
            String message,
            String path) {

        ErrorResponse response = new ErrorResponse(
                Instant.now(),
                status.value(),
                error,
                message,
                path
        );

        return ResponseEntity.status(status).body(response);
    }
}