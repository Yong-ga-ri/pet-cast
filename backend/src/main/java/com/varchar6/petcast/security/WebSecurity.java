package com.varchar6.petcast.security;

import com.varchar6.petcast.security.filter.DaoAuthenticationFilter;
import com.varchar6.petcast.security.filter.JwtFilter;
import com.varchar6.petcast.security.provider.ProviderManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
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
    private final Environment environment;
    private final ProviderManager providerManager;

    @Autowired
    public WebSecurity(
            Environment environment,
            ProviderManager providerManager
    ) {
        this.environment = environment;
        this.providerManager = providerManager;
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
                .addFilterBefore(new JwtFilter(providerManager), UsernamePasswordAuthenticationFilter.class)
                .addFilter(new DaoAuthenticationFilter(providerManager, environment));

        return http.build();
    }
}
