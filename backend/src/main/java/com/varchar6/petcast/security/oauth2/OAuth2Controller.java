package com.varchar6.petcast.security.oauth2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.varchar6.petcast.security.oauth2.service.OAuth2AccessTokenService;
import com.varchar6.petcast.security.oauth2.vo.OAuth2TokenResponseVO;
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
    public void login(@RequestParam String code) throws JsonProcessingException {
        log.debug("code: {}", code);
        OAuth2TokenResponseVO tokenVO = oAuth2AccessTokenService.getAccessToken(code);
        log.debug("access token: {}", tokenVO.getAccess_token());
        log.debug("refresh token: {}", tokenVO.getRefresh_token());
        log.debug("token expires in: {}", tokenVO.getExpires_in());
        log.debug("refresh token expires in: {}", tokenVO.getRefresh_token_expires_in());
        log.debug("scope: {}", tokenVO.getScope());
//        tokenVO.get
        log.debug("tokenVO: {}", tokenVO);
    }
}
