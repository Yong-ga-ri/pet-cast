package com.varchar6.petcast.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.varchar6.petcast.domain.member.query.vo.LoginRequestVO;
import com.varchar6.petcast.security.provider.ProviderManager;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Objects;

@Slf4j
public class DaoAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final Environment environment;
    private final ProviderManager providerManager;

    public DaoAuthenticationFilter(ProviderManager providerManager, Environment environment) {
        this.providerManager = providerManager;
        this.environment = environment;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.debug("attemptAuthentication in DaoAuthenticationFilter called");
        try {
            LoginRequestVO loginRequestVO = new ObjectMapper().readValue(request.getInputStream(), LoginRequestVO.class);
            return providerManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequestVO.getLoginId(), loginRequestVO.getPassword(), new ArrayList<>()
                    )
            );
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult
    ) {
        Claims claims = Jwts.claims().setSubject(authResult.getName());
        claims.put("authorities", authResult.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList());

        String token = Jwts.builder()
                .setClaims(claims)
                .setExpiration(
                        new Date(
                                System.currentTimeMillis()
                                        + Long.parseLong(
                                        Objects.requireNonNull(
                                                environment.getProperty("token.expiration_time")
                                        )
                                )
                        )
                )
                .signWith(SignatureAlgorithm.HS512, environment.getProperty("token.secret"))
                .compact();
        response.addHeader("token", token);
    }
}
