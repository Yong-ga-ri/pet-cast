package com.varchar6.petcast.security.jwt.provider;

import com.varchar6.petcast.domain.member.query.service.MemberAuthenticationService;
import com.varchar6.petcast.security.jwt.token.JwtAuthenticationRefreshToken;
import com.varchar6.petcast.security.jwt.service.RefreshTokenService;
import com.varchar6.petcast.security.utility.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class RefreshTokenAuthenticationProvider implements AuthenticationProvider {

    private final JwtUtil jwtUtil;
    private final MemberAuthenticationService memberAuthenticationService;
    private final RefreshTokenService refreshTokenService;

    @Autowired
    public RefreshTokenAuthenticationProvider(
            JwtUtil jwtUtil,
            RefreshTokenService refreshTokenService,
            MemberAuthenticationService memberAuthenticationService
            ) {
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
        this.memberAuthenticationService = memberAuthenticationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("RefreshTokenAuthenticationProvider called");
        String token = authentication.getCredentials().toString();
        String loginId = jwtUtil.getLoginId(token);
        if (refreshTokenService.checkRefreshTokenInRedis(loginId, token)) {
            log.debug("refresh token is valid in redis");

            UserDetails savedUser = memberAuthenticationService.loadUserByUsername(loginId);
            return new UsernamePasswordAuthenticationToken(savedUser, savedUser.getPassword(), savedUser.getAuthorities());
        }
        throw new IllegalArgumentException("invalid token");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationRefreshToken.class.isAssignableFrom(authentication);
    }
}
