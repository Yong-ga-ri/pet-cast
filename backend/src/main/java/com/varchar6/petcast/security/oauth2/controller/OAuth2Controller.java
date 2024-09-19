package com.varchar6.petcast.security.oauth2.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.varchar6.petcast.security.oauth2.service.OAuth2AccessTokenService;
import com.varchar6.petcast.security.oauth2.vo.google.GoogleUserInformationVO;
import com.varchar6.petcast.security.oauth2.vo.naver.NaverUserInformationVO;
import com.varchar6.petcast.security.oauth2.vo.responsetoken.KakaoOAuth2TokenResponseVO;
import com.varchar6.petcast.security.oauth2.vo.kakao.KakaoUserInformationVO;
import com.varchar6.petcast.security.oauth2.vo.responsetoken.NaverOAuth2TokenResponseVO;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/v1/login/oauth2")
public class OAuth2Controller {

    private final OAuth2AccessTokenService oAuth2AccessTokenService;

    public OAuth2Controller(OAuth2AccessTokenService oAuth2AccessTokenService) {
        this.oAuth2AccessTokenService = oAuth2AccessTokenService;
    }

    @GetMapping("/code/kakao")
    public KakaoUserInformationVO kakaoLogin(@RequestParam String code) throws JsonProcessingException {
        log.debug("kakaoLogin called in OAuth2Controller");
        KakaoOAuth2TokenResponseVO tokenVO = oAuth2AccessTokenService.getAccessTokenFromKakao(code);
        return oAuth2AccessTokenService.requestKakaoUserInfo(tokenVO.getAccess_token());
    }

    @GetMapping("/code/naver")
    public NaverUserInformationVO naverLogin(@RequestParam String code) throws JsonProcessingException {
        log.debug("naverLogin called in OAuth2Controller");
        String accessToken = oAuth2AccessTokenService.getAccessTokenFromNaver(code);
        return oAuth2AccessTokenService.requestNaverUserInfo(accessToken);
    }

    @GetMapping("/code/google")
    public GoogleUserInformationVO googleLogin(@RequestParam String code) throws JsonProcessingException {
        log.debug("googleLogin called in OAuth2Controller");

        String tokenVO = oAuth2AccessTokenService.getAccessTokenFromGoogle(code);
        return oAuth2AccessTokenService.requestGoogleUserInfo(tokenVO);
    }
}
