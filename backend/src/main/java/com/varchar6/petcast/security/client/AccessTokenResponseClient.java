package com.varchar6.petcast.security.client;


import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

@Slf4j
@Component
public class AccessTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
    private final RestTemplate restTemplate;

    @Autowired
    public AccessTokenResponseClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {
        log.debug("getTokenResponse called");
        String authorizationCode = authorizationCodeGrantRequest.getAuthorizationExchange().getAuthorizationResponse().getCode();
        log.debug("authorizationCode: {}", authorizationCode);
        String tokenUri = "https://kauth.kakao.com/oauth/token"; // Token URI
        String clientId = "your-client-id"; // Replace with your client ID
        String clientSecret = "your-client-secret"; // Replace with your client secret
        String redirectUri = "http://localhost:3000"; // Replace with your redirect URI

        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(tokenUri)
                .queryParam("grant_type", "authorization_code")
                .queryParam("client_id", clientId)
                .queryParam("client_secret", clientSecret)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("code", authorizationCode);

        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> request = new HttpEntity<>(headers);

        // 로그 찍기 전에 요청 URI 출력
        System.out.println("Request URI: " + uriBuilder.toUriString());

        ResponseEntity<Map> response = restTemplate.exchange(
                uriBuilder.toUriString(),
                HttpMethod.POST,
                request,
                Map.class
        );

        Map<String, String> body = response.getBody();
        if (body == null) {
            throw new RuntimeException("Failed to retrieve access token");
        }

        String accessToken = body.get("access_token");
        String refreshToken = body.get("refresh_token");
        int expiresIn = Integer.parseInt(body.get("expires_in"));

        // 로그 찍기
        System.out.println("Access Token: " + accessToken);
        System.out.println("Refresh Token: " + refreshToken);
        System.out.println("Expires In: " + expiresIn);

        return OAuth2AccessTokenResponse.withToken(accessToken)
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .refreshToken(refreshToken)
                .expiresIn(expiresIn)
                .build();
    }
}
