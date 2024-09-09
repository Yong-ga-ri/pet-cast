package com.varchar6.petcast.security.filter;

import com.varchar6.petcast.utility.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class JwtFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;

    public JwtFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        log.debug("jwt Filter called");
        String authorizationHeader = request.getHeader("Authorization");

        // 헤더가 있는지 확인
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.replace("Bearer ", "");

            // 토큰이 유효한지 확인
            if (jwtUtil.validateToken(token)) {
                SecurityContextHolder.getContext()
                        .setAuthentication(
                        jwtUtil.getAuthentication(token)
                );
            }
        }
        log.debug("no authentication with jwt Filter");
        filterChain.doFilter(request, response);

    }
}
