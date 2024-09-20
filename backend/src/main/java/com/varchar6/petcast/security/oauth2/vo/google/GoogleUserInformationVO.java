package com.varchar6.petcast.security.oauth2.vo.google;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.varchar6.petcast.security.oauth2.vo.naver.NaverUserInformationProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ToString
@Setter
@Getter
public class GoogleUserInformationVO {
    private String id;
    private String email;

    @JsonProperty("verified_email")
    private String verifiedEmail;

    private String name;

    @JsonProperty("given_name")
    private String givenName;

    @JsonProperty("family_name")
    private String familyName;

    private String picture;
}
