package com.varchar6.petcast.security.oauth2.vo.naver;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ToString
@Setter
@Getter
public class NaverUserInformationProperty {
    private String id;
    private String nickname;

    @JsonProperty("profile_image")
    private String profileImage;

    private String email;
    private String name;
}
