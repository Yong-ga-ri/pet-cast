package com.varchar6.petcast.security.provider;

import com.varchar6.petcast.utility.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JWTAuthenticationProvider implements AuthenticationProvider {

    private final JwtUtil jwtUtil;

    @Autowired
    public JWTAuthenticationProvider(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        isValid(authentication.getCredentials().toString());
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {

        // TODO: JWTAuthenticationToken 클래스로 지원할 수 있는 클래스 생성
        return false;
    }

    private void isValid(String token) {
        log.info("토큰 값: {}", token);
        if (jwtUtil.validateToken(token)) {
            log.info("유효성 통과!");
            Authentication authentication = jwtUtil.getAuthentication(token);
            log.info("JwtFilter를 통과한 유효한 토큰을 통해 security가 관리할 principal: {}", authentication);
            SecurityContextHolder.getContext().setAuthentication(authentication); // 인증 완료. 이후 필터 적용 X
        }
        throw new RuntimeException("invalid token");
    }
}
