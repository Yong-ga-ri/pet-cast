package com.varchar6.petcast.security.jwt.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class RefreshTokenService {
    private final StringRedisTemplate redisTemplate;
    private final Environment environment;

    @Autowired
    public RefreshTokenService(StringRedisTemplate redisTemplate, Environment environment) {
        this.redisTemplate = redisTemplate;
        this.environment = environment;
    }


    public void saveRefreshToken(String loginId, String refreshToken) {
        long expirationTime = Long.parseLong(Objects.requireNonNull(environment.getProperty("token.refresh.expiration_time")));
        redisTemplate.opsForValue().set(loginId, refreshToken, expirationTime, TimeUnit.MILLISECONDS);
        log.debug("refresh token expires in {} seconds", expirationTime);
        log.debug("refresh token saved");
    }

    public String getRefreshToken(String loginId) {
        return redisTemplate.opsForValue().get(loginId);
    }

    public void deleteRefreshToken(String loginId) {
        redisTemplate.delete(loginId);
    }

    public boolean checkRefreshTokenInRedis(String loginId, String refreshToken) {
        log.debug("check refresh token in redis");
        return refreshToken.equals(getRefreshToken(loginId));
    }
}
