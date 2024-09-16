package com.varchar6.petcast.security.domain;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Getter
public class CustomUser implements UserDetails {
    private final int id;
    private final String username;
    private final String password;
    private final String name;
    private final String phone;
    private final String nickname;
    private final String image;
    private final String createdAt;
    private final String updatedAt;
    private final boolean active;
    private final String introduction;
    private final Collection<? extends GrantedAuthority> authorities;

    public CustomUser(
            int id,
            String username,
            String password,
            String name,
            String phone,
            String nickname,
            String image,
            String createdAt,
            String updatedAt,
            boolean active,
            String introduction,
            Collection<? extends GrantedAuthority> authorities) {
        super();
        this.id = id;
        this.username = username;
        this.password = password;
        this.name = name;
        this.phone = phone;
        this.nickname = nickname;
        this.image = image;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.active = active;
        this.introduction = introduction;
        this.authorities = authorities;
    }

}
