package com.varchar6.petcast.security.config;

import com.varchar6.petcast.security.dao.DaoAuthenticationFilter;
import com.varchar6.petcast.security.jwt.filter.JwtAccessTokenFilter;
import com.varchar6.petcast.security.jwt.filter.JwtRefreshTokenFilter;
import com.varchar6.petcast.security.oauth2.CustomAuthorizationCodeTokenResponseClient;
import com.varchar6.petcast.security.oauth2.CustomHttpSessionOAuth2AuthorizationRequestRepository;
import com.varchar6.petcast.security.oauth2.repository.StatelessAuthorizationRequestRepository;
import com.varchar6.petcast.security.oauth2.service.CustomOAuth2UserService;
import com.varchar6.petcast.security.provider.ProviderManager;
import com.varchar6.petcast.security.utility.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurity {
    private final JwtUtil jwtUtil;
    private final ProviderManager providerManager;
    private final LogoutHandler logoutHandler;
    private final LogoutSuccessHandler logoutSuccessHandler;
    private final CustomOAuth2UserService oAuth2UserService;
//    private final StatelessAuthorizationRequestRepository statelessAuthorizationRequestRepository;
    private final CustomHttpSessionOAuth2AuthorizationRequestRepository customHttpSessionOAuth2AuthorizationRequestRepository;
    private final AuthenticationSuccessHandler oAuthAuthenticationSuccessHandler;

    @Autowired
    public WebSecurity(
            JwtUtil jwtUtil,
            ProviderManager providerManager,
            LogoutHandler logoutHandler,
            LogoutSuccessHandler logoutSuccessHandler,
            CustomOAuth2UserService oAuth2UserService,
//            StatelessAuthorizationRequestRepository statelessAuthorizationRequestRepository,
            CustomHttpSessionOAuth2AuthorizationRequestRepository customHttpSessionOAuth2AuthorizationRequestRepository,
            AuthenticationSuccessHandler oAuthAuthenticationSuccessHandler
    ) {
        this.jwtUtil = jwtUtil;
        this.providerManager = providerManager;
        this.logoutHandler = logoutHandler;
        this.logoutSuccessHandler = logoutSuccessHandler;
//        this.statelessAuthorizationRequestRepository = statelessAuthorizationRequestRepository;
        this.customHttpSessionOAuth2AuthorizationRequestRepository = customHttpSessionOAuth2AuthorizationRequestRepository;
        this.oAuth2UserService = oAuth2UserService;
        this.oAuthAuthenticationSuccessHandler = oAuthAuthenticationSuccessHandler;
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)  // csrf 비활성화
                .authenticationManager(providerManager)       // authenticationManager 등록
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))    // 세션 비활성화

                // 요청에 대한 권한 설정
                .authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers(new AntPathRequestMatcher("/**")).permitAll()     // for dev
                        .requestMatchers(new AntPathRequestMatcher("/login")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/api/v1/members/sign-up")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/api/v1/oauth2/authorization/**")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/api/v1/login/oauth2/**")).permitAll()
//                        .requestMatchers(new AntPathRequestMatcher("/api/v1/members/sign-up")).permitAll()
//                        .requestMatchers(new AntPathRequestMatcher("/api/v1/notice", "POST")).hasRole(Role.ADMIN.getType())
//                        .requestMatchers(new AntPathRequestMatcher("/api/v1/**")).hasRole(Role.CUSTOMER.getType())
                        .anyRequest().authenticated()
                )
                .logout(
                        logout -> logout
                                .logoutUrl("/api/v1/auth/logout")
                                .addLogoutHandler(logoutHandler)
                                .logoutSuccessHandler(logoutSuccessHandler)
                )
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(authorization -> authorization
//                                .authorizationRequestRepository(statelessAuthorizationRequestRepository)
                                .authorizationRequestRepository(customHttpSessionOAuth2AuthorizationRequestRepository)
                        )
                        .tokenEndpoint(token -> token
                                .accessTokenResponseClient(new CustomAuthorizationCodeTokenResponseClient()) // 커스텀 토큰 응답 클라이언트 설정
                        )
                        .successHandler(oAuthAuthenticationSuccessHandler)
                        .userInfoEndpoint(userInfoConfig ->
                                        userInfoConfig.userService(oAuth2UserService)
                        )
                )
                .addFilterBefore(new JwtAccessTokenFilter(providerManager), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtRefreshTokenFilter(providerManager, jwtUtil), UsernamePasswordAuthenticationFilter.class)
                .addFilter(new DaoAuthenticationFilter(providerManager, jwtUtil));

        return http.build();
    }
}
