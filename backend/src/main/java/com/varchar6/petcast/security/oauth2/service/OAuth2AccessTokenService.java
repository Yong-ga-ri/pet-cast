package com.varchar6.petcast.security.oauth2.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.varchar6.petcast.security.oauth2.vo.naver.NaverUserInformationVO;
import com.varchar6.petcast.security.oauth2.vo.responsetoken.KakaoOAuth2TokenResponseVO;
import com.varchar6.petcast.security.oauth2.vo.kakao.KakaoUserInformationVO;
import com.varchar6.petcast.security.oauth2.vo.responsetoken.NaverOAuth2TokenResponseVO;
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
    private final ObjectMapper objectMapper;

    // kakao settings
    @Value("${spring.security.oauth2.client.registration.kakao.authorization-grant-type}")
    private String kakaoGrantType;

    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String kakaoClientId;

    @Value("${spring.security.oauth2.client.provider.kakao.token-uri}")
    private String kakaoTokenUri;

    @Value("${spring.security.oauth2.client.registration.kakao.client-secret}")
    private String kakaoClientSecret;

    @Value("${spring.security.oauth2.client.registration.kakao.redirect-uri}")
    private String kakaoRedirectUri;

    @Value("${spring.security.oauth2.client.provider.kakao.user-info-uri}")
    private String kakaoUserInfoUri;

    // kakao settings
    @Value("${spring.security.oauth2.client.registration.naver.authorization-grant-type}")
    private String naverGrantType;

    @Value("${spring.security.oauth2.client.registration.naver.client-id}")
    private String naverClientId;

    @Value("${spring.security.oauth2.client.provider.naver.token-uri}")
    private String naverTokenUri;

    @Value("${spring.security.oauth2.client.registration.naver.client-secret}")
    private String naverClientSecret;

    @Value("${spring.security.oauth2.client.registration.naver.redirect-uri}")
    private String naverRedirectUri;

    @Value("${spring.security.oauth2.client.provider.naver.user-info-uri}")
    private String naverUserInfoUri;

    // google settings
    @Value("${spring.security.oauth2.client.registration.google.authorization-grant-type}")
    private String googleGrantType;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @Value("${spring.security.oauth2.client.provider.google.token-uri}")
    private String googleTokenUri;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String googleClientSecret;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String googleRedirectUri;

    @Value("${spring.security.oauth2.client.provider.google.user-info-uri}")
    private String googleUserInfoUri;


    public OAuth2AccessTokenService(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    public KakaoOAuth2TokenResponseVO getAccessTokenFromKakao(String authorizationCode) throws JsonProcessingException {
        // 헤더 설정
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // 요청 바디에 필요한 파라미터 설정
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", kakaoGrantType);
        body.add("client_id", kakaoClientId);
        body.add("client_secret", kakaoClientSecret);
        body.add("redirect_uri", kakaoRedirectUri);
        body.add("code", authorizationCode);
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);
        // POST 요청으로 토큰 받기

        String tokenResponse = restTemplate.exchange(kakaoTokenUri, HttpMethod.POST, entity, String.class).getBody();

        KakaoOAuth2TokenResponseVO kakaoOAuth2TokenResponseVO = null;
        try {
            kakaoOAuth2TokenResponseVO = objectMapper.readValue(tokenResponse, KakaoOAuth2TokenResponseVO.class);
        } catch (JsonProcessingException e) {
            log.error(e.getMessage());
        }

        return kakaoOAuth2TokenResponseVO;

    }

    public String getAccessTokenFromNaver(String authorizationCode) throws JsonProcessingException {
        // 헤더 설정
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // 요청 바디에 필요한 파라미터 설정
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", naverGrantType);
        body.add("client_id", naverClientId);
        body.add("client_secret", naverClientSecret);
        body.add("redirect_uri", naverRedirectUri);
        body.add("code", authorizationCode);
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);
        // POST 요청으로 토큰 받기

        String tokenResponse = restTemplate.exchange(naverTokenUri, HttpMethod.POST, entity, String.class).getBody();

        NaverOAuth2TokenResponseVO naverOAuth2TokenResponseVO = null;
        try {
            naverOAuth2TokenResponseVO = objectMapper.readValue(tokenResponse, NaverOAuth2TokenResponseVO.class);
        } catch (JsonProcessingException e) {
            log.error(e.getMessage());
        }
        log.debug("naver tokenResponse: {}", naverOAuth2TokenResponseVO);

        assert naverOAuth2TokenResponseVO != null;
        return naverOAuth2TokenResponseVO.getAccess_token();

    }


    public String getAccessTokenFromGoogle(String authorizationCode) throws JsonProcessingException {
        // 헤더 설정
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // 요청 바디에 필요한 파라미터 설정
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();

        body.add("grant_type", googleGrantType);
        body.add("client_id", googleClientId);
        body.add("client_secret", googleClientSecret);
        body.add("redirect_uri", googleRedirectUri);
        body.add("code", authorizationCode);
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);
        // POST 요청으로 토큰 받기
        log.debug("authorizationCode: {}", authorizationCode);

        String tokenResponse = restTemplate.exchange(googleTokenUri, HttpMethod.POST, entity, String.class).getBody();

        log.debug("tokenResponse: {}", tokenResponse);
//        KakaoOAuth2TokenResponseVO kakaoOAuth2TokenResponseVO = null;
//        try {
//            kakaoOAuth2TokenResponseVO = objectMapper.readValue(tokenResponse, KakaoOAuth2TokenResponseVO.class);
//        } catch (JsonProcessingException e) {
//            log.error(e.getMessage());
//        }

        return tokenResponse;

    }

    public KakaoUserInformationVO requestKakaoUserInfo(String accessToken) throws JsonProcessingException {
        // 헤더에 Access Token 추가
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<String> entity = new HttpEntity<>(headers);

        // GET 요청으로 사용자 정보 가져오기
        ResponseEntity<String> response = restTemplate.exchange(kakaoUserInfoUri, HttpMethod.GET, entity, String.class);
        log.debug("response: {}", response);
        log.debug("response.getBody(): {}", response.getBody());
        KakaoUserInformationVO kakaoUserInformation = objectMapper.readValue(response.getBody(), KakaoUserInformationVO.class);
        log.debug("kakaoUserInformation: {}", kakaoUserInformation);
        return kakaoUserInformation;

    }

    public NaverUserInformationVO requestNaverUserInfo(String accessToken) throws JsonProcessingException {
        // 헤더에 Access Token 추가
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        log.debug("accessToken: {}", accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        // GET 요청으로 사용자 정보 가져오기
        ResponseEntity<String> response = restTemplate.exchange(naverUserInfoUri, HttpMethod.GET, entity, String.class);
        log.debug("response: {}", response);
        NaverUserInformationVO naverUserInformation = objectMapper.readValue(response.getBody(), NaverUserInformationVO.class);
        log.debug("naverUserInformation: {}", naverUserInformation);
        return naverUserInformation;

    }
}
