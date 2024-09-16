package com.varchar6.petcast.security.dao;

import com.varchar6.petcast.domain.member.query.service.MemberAuthenticationService;
import com.varchar6.petcast.security.jwt.service.RefreshTokenService;
import com.varchar6.petcast.security.utility.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;


@Slf4j
@Component
public class DaoAuthenticationProvider implements AuthenticationProvider {
    private final MemberAuthenticationService memberAuthenticationService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final JwtUtil jwtUtil;

    @Autowired
    public DaoAuthenticationProvider(
            MemberAuthenticationService memberAuthenticationService,
            BCryptPasswordEncoder bCryptPasswordEncoder,
            RefreshTokenService refreshTokenService,
            JwtUtil jwtUtil
    ) {
        this.memberAuthenticationService = memberAuthenticationService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.refreshTokenService = refreshTokenService;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String loginId = authentication.getPrincipal().toString();
        String tryPassword = authentication.getCredentials().toString();

        UserDetails savedUser = memberAuthenticationService.loadUserByUsername((authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName());

        if (!bCryptPasswordEncoder.matches(tryPassword, savedUser.getPassword())) {
            throw new BadCredentialsException("Bad credentials");
        } else {
            Authentication authenticationResult = new UsernamePasswordAuthenticationToken(savedUser, savedUser.getPassword(), savedUser.getAuthorities());
            String refreshToken = jwtUtil.generateRefreshToken(authenticationResult);
            refreshTokenService.saveRefreshToken(loginId, refreshToken);
            return authenticationResult;
        }

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
