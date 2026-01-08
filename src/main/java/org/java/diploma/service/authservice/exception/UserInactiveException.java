package org.java.diploma.service.authservice.exception;

public class UserInactiveException extends RuntimeException {
    public UserInactiveException(String message) {
        super(message);
    }
}
