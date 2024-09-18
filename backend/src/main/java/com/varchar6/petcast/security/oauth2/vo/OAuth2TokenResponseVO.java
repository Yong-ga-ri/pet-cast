package com.varchar6.petcast.security.oauth2.vo;

import lombok.Getter;
import lombok.ToString;

@ToString
@Getter
public class OAuth2TokenResponseVO {
    private String access_token;
    private String token_type;
    private String refresh_token;
    private Double expires_in;
    private String scope;
    private Double refresh_token_expires_in;

}
