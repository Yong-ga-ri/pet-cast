package com.varchar6.petcast.security.oauth2.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.varchar6.petcast.security.oauth2.vo.OAuth2TokenResponseVO;
import com.varchar6.petcast.security.oauth2.vo.kakao.KakaoUserInformationVO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;

@Slf4j
@Service
public class OAuth2AccessTokenService {
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public OAuth2AccessTokenService(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    @Value("${spring.security.oauth2.client.registration.kakao.authorization-grant-type}")
    private String grantType;

    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.provider.kakao.token-uri}")
    private String tokenUri;

    @Value("${spring.security.oauth2.client.registration.kakao.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.kakao.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.provider.kakao.user-info-uri}")
    private String userInfoUri;

    public OAuth2TokenResponseVO getAccessToken(String authorizationCode) throws JsonProcessingException {
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
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);
        // POST 요청으로 토큰 받기

        String tokenResponse = restTemplate.exchange(tokenUri, HttpMethod.POST, entity, String.class).getBody();

        OAuth2TokenResponseVO oAuth2TokenResponseVO = null;
        try {
            oAuth2TokenResponseVO = objectMapper.readValue(tokenResponse, OAuth2TokenResponseVO.class);
        } catch (JsonProcessingException e) {
            log.error(e.getMessage());
        }

        return oAuth2TokenResponseVO;

    }

    public KakaoUserInformationVO requestUserInfo(String accessToken) throws JsonProcessingException {
        // 헤더에 Access Token 추가
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<String> entity = new HttpEntity<>(headers);

        // GET 요청으로 사용자 정보 가져오기
        ResponseEntity<String> response = restTemplate.exchange(userInfoUri, HttpMethod.GET, entity, String.class);
        log.debug("response: {}", response);
        log.debug("response.getBody(): {}", response.getBody());
        KakaoUserInformationVO kakaoUserInformation = objectMapper.readValue(response.getBody(), KakaoUserInformationVO.class);
        log.debug("kakaoUserInformation: {}", kakaoUserInformation);
        return kakaoUserInformation;

    }
}
