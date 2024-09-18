package com.varchar6.petcast.security.oauth2.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.varchar6.petcast.security.oauth2.service.OAuth2AccessTokenService;
import com.varchar6.petcast.security.oauth2.vo.OAuth2TokenResponseVO;
import com.varchar6.petcast.security.oauth2.vo.kakao.KakaoUserInformationVO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/login/oauth2")
public class OAuth2Controller {

    private final OAuth2AccessTokenService oAuth2AccessTokenService;

    public OAuth2Controller(OAuth2AccessTokenService oAuth2AccessTokenService) {
        this.oAuth2AccessTokenService = oAuth2AccessTokenService;
    }

    @GetMapping("/code/kakao")
    public KakaoUserInformationVO login(@RequestParam String code) throws JsonProcessingException {
        OAuth2TokenResponseVO tokenVO = oAuth2AccessTokenService.getAccessToken(code);
        return oAuth2AccessTokenService.requestUserInfo(tokenVO.getAccess_token());
    }
}
