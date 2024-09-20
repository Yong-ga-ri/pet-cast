package com.varchar6.petcast.security.logout.handler;

import com.varchar6.petcast.security.jwt.service.RefreshTokenService;
import com.varchar6.petcast.security.utility.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class CustomLogoutHandler implements LogoutHandler {
    private final RefreshTokenService refreshTokenService;
    private final JwtUtil jwtUtil;

    public CustomLogoutHandler(RefreshTokenService refreshTokenService, JwtUtil jwtUtil) {
        this.refreshTokenService = refreshTokenService;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        log.debug("CustomLogoutHandler called");

        // if front-end manage token with cookie

        // if SecurityContextHolder used in Spring security, Clear the SecurityContextHolderStrategy (SecurityContextLogoutHandler)
        //   Clear the SecurityContextRepository (SecurityContextLogoutHandler)


        // Clean up any authentication (TokenRememberMeServices)
        // Clean refresh token in redis
        String accessToken = request.getHeader("Authorization").replace("Bearer ", "");
        if (jwtUtil.isTokenValidate(accessToken)) {
            refreshTokenService.deleteRefreshToken(
                    jwtUtil.getLoginId(accessToken)
            );
        }

    }
}
