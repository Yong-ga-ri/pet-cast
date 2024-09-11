package com.varchar6.petcast.security;

import com.varchar6.petcast.security.filter.DaoAuthenticationFilter;
import com.varchar6.petcast.security.filter.JwtAccessTokenFilter;
import com.varchar6.petcast.security.filter.JwtRefreshTokenFilter;
import com.varchar6.petcast.security.provider.ProviderManager;
import com.varchar6.petcast.utility.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurity {
    private final ProviderManager providerManager;
    private final JwtUtil jwtUtil;

    @Autowired
    public WebSecurity(
            ProviderManager providerManager,
            JwtUtil jwtUtil
    ) {
        this.providerManager = providerManager;
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)  // csrf 비활성화
                .authenticationManager(providerManager)       // authenticationManager 등록
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))    // 세션 비활성화

                // 요청에 대한 권한 설정
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(new AntPathRequestMatcher("/**")).permitAll()     // for dev
//                        .requestMatchers(new AntPathRequestMatcher("/login")).permitAll()
//                        .requestMatchers(new AntPathRequestMatcher("/api/v1/members/sign-up")).permitAll()
//                        .requestMatchers(new AntPathRequestMatcher("/api/v1/notice", "POST")).hasRole(Role.ADMIN.getType())
//                        .requestMatchers(new AntPathRequestMatcher("/api/v1/**")).hasRole(Role.CUSTOMER.getType())
                        .anyRequest().authenticated()
                )
                .addFilterBefore(new JwtAccessTokenFilter(providerManager), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtRefreshTokenFilter(providerManager, jwtUtil), UsernamePasswordAuthenticationFilter.class)
                .addFilter(new DaoAuthenticationFilter(providerManager, jwtUtil));

        return http.build();
    }
}
