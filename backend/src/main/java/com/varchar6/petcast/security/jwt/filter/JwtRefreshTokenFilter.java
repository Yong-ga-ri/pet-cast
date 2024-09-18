package com.varchar6.petcast.security.jwt.filter;

import com.varchar6.petcast.security.jwt.token.JwtAuthenticationRefreshToken;
import com.varchar6.petcast.security.utility.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class JwtRefreshTokenFilter extends OncePerRequestFilter {
    private final AuthenticationManager providerManager;
    private final AntPathRequestMatcher refreshTokenRequestMatcher;
    private final JwtUtil jwtUtil;

    public JwtRefreshTokenFilter(AuthenticationManager providerManager, JwtUtil jwtUtil) {
        this.providerManager = providerManager;
        this.refreshTokenRequestMatcher = new AntPathRequestMatcher("/api/v1/auth/refresh", "POST");
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        if (refreshTokenRequestMatcher.matches(request)) {
            String authorizationHeader = request.getHeader("Authorization");
            log.debug("JwtRefreshTokenFilter called");

            // 헤더가 있는지 확인
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                String accessToken = jwtUtil.generateAccessToken(
                        providerManager.authenticate(
                                new JwtAuthenticationRefreshToken(authorizationHeader.replace("Bearer ", ""))
                        )
                );

                response.addHeader("Access-Token", accessToken);
                return;
            }
        }
        log.debug("do next filter from JwtRefreshTokenFilter");
        filterChain.doFilter(request, response);
    }
}
