package com.varchar6.petcast.security.oauth2.vo.responsetoken;

import lombok.Getter;
import lombok.ToString;

@ToString
@Getter
public class NaverOAuth2TokenResponseVO {
    private String access_token;
    private String token_type;
    private String refresh_token;
    private String expires_in;

}
