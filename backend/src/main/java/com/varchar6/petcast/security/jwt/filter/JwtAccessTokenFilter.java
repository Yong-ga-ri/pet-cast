package com.varchar6.petcast.security.jwt.filter;


import com.varchar6.petcast.security.jwt.token.JwtAuthenticationAccessToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class JwtAccessTokenFilter extends OncePerRequestFilter {
    private final AuthenticationManager providerManager;
    private final AntPathRequestMatcher signUpExcludePathMatcher;
    private final AntPathRequestMatcher refreshExcludePathMatcher;
    private final AntPathRequestMatcher loginExcludePathMatcher;
    private final AntPathRequestMatcher oAuthAuthenticationExcludePathMatcher;
    private final AntPathRequestMatcher oAuthExcludePathMatcher;

    public JwtAccessTokenFilter(AuthenticationManager providerManager) {
        this.providerManager = providerManager;
        this.signUpExcludePathMatcher = new AntPathRequestMatcher("/api/v1/members/sign-up", "POST");
        this.refreshExcludePathMatcher = new AntPathRequestMatcher("/api/v1/auth/refresh", "POST");
        this.loginExcludePathMatcher = new AntPathRequestMatcher("/login", "POST");
        this.oAuthAuthenticationExcludePathMatcher = new AntPathRequestMatcher("/api/v1/oauth2/authorization/**", "GET");
        this.oAuthExcludePathMatcher = new AntPathRequestMatcher("/api/v1/login/oauth2/code/**", "GET");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        if (
                signUpExcludePathMatcher.matches(request)
                        || refreshExcludePathMatcher.matches(request)
                        || oAuthAuthenticationExcludePathMatcher.matches(request)
                        || loginExcludePathMatcher.matches(request)
                        || oAuthExcludePathMatcher.matches(request)
        ) {
            log.debug("JwtAccessTokenFilter skipped");
            filterChain.doFilter(request, response);
        } else {
            String authorizationHeader = request.getHeader("Authorization");
            log.debug("JwtAccessTokenFilter called");
            log.debug("request.getUri(): {}", request.getRequestURI());

            try {
                // 헤더가 있는지 확인
                if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                    providerManager.authenticate(
                            new JwtAuthenticationAccessToken(authorizationHeader.replace("Bearer ", ""))
                    );
                    filterChain.doFilter(request, response);
                } else {
                    throw new JwtException("Invalid or Missing JWT Token");
                }
            } catch (JwtException e) {
                // JWT가 유효하지 않으면 즉시 401 Unauthorized 반환
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\": \"Unauthorized\", \"message\": \"" + e.getMessage() + "\"}");
                response.setContentType("application/json");
            }
        }
    }
}
