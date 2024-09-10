package com.varchar6.petcast.security.filter;

import com.varchar6.petcast.security.JwtAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
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

        // 헤더가 있는지 확인
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            SecurityContextHolder.getContext().setAuthentication(
                    providerManager.authenticate(
                            new JwtAuthenticationToken(authorizationHeader.replace("Bearer ", ""))
                    )
            ); // 인증 완료. 이후 필터 적용 X
        }
        filterChain.doFilter(request, response);

    }
}
