package com.varchar6.petcast.security.handler.logout;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class CustomLogoutHandler implements LogoutHandler {
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        // if front-end manage token with cookie
//        request.getSession().invalidate();

        log.debug("CustomLogoutHandler called");

        // TODO: Clear the SecurityContextHolderStrategy (SecurityContextLogoutHandler)
        // TODO: Clear the SecurityContextRepository (SecurityContextLogoutHandler)
        // TODO: Clean up any authentication (TokenRememberMeServices)
        // TODO: Clean refresh token in redis

    }
}
