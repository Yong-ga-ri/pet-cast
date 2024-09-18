package com.varchar6.petcast.security.provider;

import com.varchar6.petcast.security.exception.GlobalAuthenticationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.List;

@Slf4j
@Component
public class ProviderManager implements AuthenticationManager {
    private final List<AuthenticationProvider> providerList;

    @Autowired
    public ProviderManager(List<AuthenticationProvider> providerList) {
        this.providerList = providerList;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws GlobalAuthenticationException {
        for (AuthenticationProvider provider : providerList) {
            log.debug("searching for adequate provider.. // authentication.getClass(): {}", authentication.getClass());
            if (provider.supports(authentication.getClass())) {
                log.debug("provider selected: {}", provider.getClass().getName());
                return provider.authenticate(authentication);
            }
            log.debug("not provider selected: {}", provider.getClass().getName());
        }

        // 인증 실패 시 예외 처리
        throw new GlobalAuthenticationException("No provider found for " + authentication.getClass().getName());
    }
}
