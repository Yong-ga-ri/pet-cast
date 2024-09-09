package com.varchar6.petcast.security.provider;

import com.varchar6.petcast.domain.member.query.service.MemberAuthenticationService;
import com.varchar6.petcast.security.CustomUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
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
    private final Environment environment;

    @Autowired
    public DaoAuthenticationProvider(
            MemberAuthenticationService memberAuthenticationService,
            BCryptPasswordEncoder bCryptPasswordEncoder,
            Environment environment
    ) {
        this.memberAuthenticationService = memberAuthenticationService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.environment = environment;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String tryPassword = authentication.getCredentials().toString();

        UserDetails savedUser = memberAuthenticationService.loadUserByUsername((authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName());

        if (!bCryptPasswordEncoder.matches(tryPassword, savedUser.getPassword())) {
            throw new BadCredentialsException("Bad credentials");
        }

        return new UsernamePasswordAuthenticationToken(savedUser, tryPassword, savedUser.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}
