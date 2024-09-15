package com.varchar6.petcast.security.oauth2.service;

import com.varchar6.petcast.security.oauth2.vo.OAuth2TokenResponseVO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Service
public class OAuth2AccessTokenService {
    private final RestTemplate restTemplate;

    public OAuth2AccessTokenService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.kakao.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.kakao.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.provider.kakao.token-uri}")
    private String tokenUri;

    @Value("${spring.security.oauth2.client.registration.kakao.authorization-grant-type}")
    private String grantType;

    @Value("${spring.security.oauth2.client.provider.kakao.user-info-uri}")
    private String userInfoUri;

    public String getAccessToken(String authorizationCode) {
        // 헤더 설정
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // 요청 바디에 필요한 파라미터 설정
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", grantType);
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("redirect_uri", redirectUri);
        body.add("code", authorizationCode);

        // HttpEntity에 헤더와 바디 포함
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

        // POST 요청으로 토큰 받기
        ResponseEntity<OAuth2TokenResponseVO> tokenResponse = restTemplate.exchange(tokenUri, HttpMethod.POST, entity, String.class);
        log.debug("tokenResponse: {}", tokenResponse);

        return tokenResponse.getBody();  // JSON 형태로 토큰 정보 반환
    }
}
