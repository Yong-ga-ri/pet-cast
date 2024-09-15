package com.varchar6.petcast.security.oauth2;

import com.varchar6.petcast.security.oauth2.service.OAuth2AccessTokenService;
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
    public void login(@RequestParam String code) {
        log.debug("code: {}", code);
        String token = oAuth2AccessTokenService.getAccessToken(code);
        log.debug("token: {}", token);
    }
}
