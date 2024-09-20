package com.varchar6.petcast.security.oauth2.vo.naver;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.varchar6.petcast.security.oauth2.vo.kakao.KakaoAccount;
import com.varchar6.petcast.security.oauth2.vo.kakao.Properties;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ToString
@Setter
@Getter
public class NaverUserInformationVO {
    @JsonProperty("resultcode")
    private String resultCode;

    private String message;

    @JsonProperty("response")
    private NaverUserInformationProperty response;
}
