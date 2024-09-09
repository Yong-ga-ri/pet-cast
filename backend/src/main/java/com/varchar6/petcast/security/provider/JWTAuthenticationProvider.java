package com.varchar6.petcast.security.provider;

import com.varchar6.petcast.security.JwtAuthenticationToken;
import com.varchar6.petcast.utility.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JWTAuthenticationProvider implements AuthenticationProvider {

    private final JwtUtil jwtUtil;

    @Autowired
    public JWTAuthenticationProvider(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token = authentication.getCredentials().toString();
        if (jwtUtil.validateAccessToken(token)) {
            return jwtUtil.getAuthentication(token);
        }
        throw new IllegalArgumentException("invalid token");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
