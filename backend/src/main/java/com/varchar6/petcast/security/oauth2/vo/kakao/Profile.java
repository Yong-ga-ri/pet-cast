package com.varchar6.petcast.security.oauth2.vo.kakao;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ToString
@Setter
@Getter
public class Profile {
    private String nickname;

    @JsonProperty("thumbnail_image_url")
    private String thumbnailImageUrl;

    @JsonProperty("profile_image_url")
    private String profileImageUrl;

    @JsonProperty("is_default_image")
    private boolean isDefaultImage;

    @JsonProperty("is_default_nickname")
    private boolean isDefaultNickname;

}
