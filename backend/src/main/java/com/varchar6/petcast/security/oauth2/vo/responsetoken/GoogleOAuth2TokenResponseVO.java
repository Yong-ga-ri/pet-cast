package com.varchar6.petcast.security.oauth2.vo.responsetoken;

import lombok.Getter;
import lombok.ToString;

@ToString
@Getter
public class GoogleOAuth2TokenResponseVO {
    private String access_token;
    private String token_type;
    private String id_token;
    private String expires_in;
    private String scope;

}
