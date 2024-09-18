package com.varchar6.petcast.security.jwt.filter;

import com.varchar6.petcast.security.jwt.token.JwtAuthenticationAccessToken;
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
public class JwtAccessTokenFilter extends OncePerRequestFilter {
    private final AuthenticationManager providerManager;

    public JwtAccessTokenFilter(AuthenticationManager providerManager) {
        this.providerManager = providerManager;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        log.debug("JwtAccessTokenFilter called");
        // 헤더가 있는지 확인
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            providerManager.authenticate(
                    new JwtAuthenticationAccessToken(authorizationHeader.replace("Bearer ", ""))
            );
        }
        filterChain.doFilter(request, response);
    }
}
