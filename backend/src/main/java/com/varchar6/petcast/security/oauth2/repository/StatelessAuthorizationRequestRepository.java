package com.varchar6.petcast.security.oauth2.repository;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Base64;

@Slf4j
@Component
public class StatelessAuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    private static final String STATE_PARAMETER = "state";
    private final ObjectMapper objectMapper;

    @Autowired
    public StatelessAuthorizationRequestRepository(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        log.debug("loadAuthorizationRequest called in StatelessAuthorizationRequestRepository");
        String state = request.getParameter(STATE_PARAMETER);
        if (state == null) {
            return null;
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(state);
            return objectMapper.readValue(decoded, OAuth2AuthorizationRequest.class);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        log.debug("saveAuthorizationRequest called in StatelessAuthorizationRequestRepository");
        log.debug("request.getRequestURI(): {}", request.getRequestURI());
        if (request.getRequestURI().startsWith("/oauth2/authorization")) {
            log.debug("request.getRequestURI started with /oauth2/authorization");
            if (authorizationRequest == null) {
                log.debug("authorizationRequest is null");
                return;
            }
            try {
                String serialized = objectMapper.writeValueAsString(authorizationRequest);
                String encoded = Base64.getUrlEncoder().encodeToString(serialized.getBytes());
                request.getSession().setAttribute(STATE_PARAMETER, encoded);
            } catch (IOException e) {
                log.error("Error saving OAuth2AuthorizationRequest", e);
            }
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        log.debug("removeAuthorizationRequest called in StatelessAuthorizationRequestRepository");
        return loadAuthorizationRequest(request);
    }
}
