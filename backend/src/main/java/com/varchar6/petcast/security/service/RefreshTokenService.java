package com.varchar6.petcast.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class RefreshTokenService {

    private final StringRedisTemplate redisTemplate;

    @Autowired
    public RefreshTokenService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }


    public void saveRefreshToken(String loginId, String refreshToken, long expirationTime) {
        redisTemplate.opsForValue().set(loginId, refreshToken, expirationTime, TimeUnit.MILLISECONDS);
    }

    public String getRefreshToken(String loginId) {
        return redisTemplate.opsForValue().get(loginId);
    }

    public void deleteRefreshToken(String loginId) {
        redisTemplate.delete(loginId);
    }

    public boolean checkRefreshTokenInRedis(String loginId, String refreshToken) {
        String storedToken = getRefreshToken(loginId);
        return refreshToken.equals(storedToken);
    }
}
