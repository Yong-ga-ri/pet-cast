package com.varchar6.petcast.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.varchar6.petcast.domain.member.query.vo.LoginRequestVO;
import com.varchar6.petcast.security.provider.ProviderManager;
import com.varchar6.petcast.utility.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.ArrayList;

@Slf4j
public class DaoAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final ProviderManager providerManager;
    private final JwtUtil jwtUtil;

    public DaoAuthenticationFilter(
            ProviderManager providerManager,
            JwtUtil jwtUtil
    ) {
        this.providerManager = providerManager;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
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
        String accessToken = jwtUtil.generateToken(authResult, true);
        String refreshToken = jwtUtil.generateToken(authResult, false);

        response.addHeader("Access-Token", accessToken);
        response.addHeader("Refresh-Token", refreshToken);
    }


}
