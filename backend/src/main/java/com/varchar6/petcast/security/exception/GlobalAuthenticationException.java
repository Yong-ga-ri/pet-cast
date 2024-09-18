package com.varchar6.petcast.security.exception;

import org.springframework.security.core.AuthenticationException;

public class GlobalAuthenticationException extends AuthenticationException {
    public GlobalAuthenticationException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public GlobalAuthenticationException(String msg) {
        super(msg);
    }
}
