package com.varchar6.petcast.security.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.Map;

@Slf4j
@Component
public class CustomHttpSessionOAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    private static final String DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME = HttpSessionOAuth2AuthorizationRequestRepository.class.getName() + ".AUTHORIZATION_REQUEST";
    private final String sessionAttributeName;

    public CustomHttpSessionOAuth2AuthorizationRequestRepository() {
        this.sessionAttributeName = DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME;
    }

    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        log.debug("loadAuthorizationRequest called");
        Assert.notNull(request, "request cannot be null");
        String stateParameter = this.getStateParameter(request);
        if (stateParameter == null) {
            return null;
        } else {
            OAuth2AuthorizationRequest authorizationRequest = this.getAuthorizationRequest(request);
            return authorizationRequest != null && stateParameter.equals(authorizationRequest.getState()) ? authorizationRequest : null;
        }
    }

    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        Assert.notNull(request, "request cannot be null");
        Assert.notNull(response, "response cannot be null");
        log.debug("saveAuthorizationRequest called");
        log.debug("authorizationRequest: {}", authorizationRequest);
        String grantType = authorizationRequest.getGrantType().getValue();
        String authorizationRequestUri = authorizationRequest.getAuthorizationRequestUri();
        String responseType = authorizationRequest.getResponseType().getValue();
        String clientId = authorizationRequest.getClientId();
        String redirectUri = authorizationRequest.getRedirectUri();
        Map<String, Object> additionalParameters = authorizationRequest.getAdditionalParameters();
        Map<String, Object> attributes = authorizationRequest.getAttributes();
        log.debug("grantType: {}", grantType);
        log.debug("authorizationRequestUri: {}", authorizationRequestUri);
        log.debug("responseType: {}", responseType);
        log.debug("clientId: {}", clientId);
        log.debug("redirectUri: {}", redirectUri);
        if (authorizationRequest == null) {
            this.removeAuthorizationRequest(request, response);
        } else {
            String state = authorizationRequest.getState();
            Assert.hasText(state, "authorizationRequest.state cannot be empty");
            request.getSession().setAttribute(this.sessionAttributeName, authorizationRequest);
        }
    }

    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        log.debug("removeAuthorizationRequest called");
        Assert.notNull(response, "response cannot be null");
        OAuth2AuthorizationRequest authorizationRequest = this.loadAuthorizationRequest(request);
        if (authorizationRequest != null) {
            request.getSession().removeAttribute(this.sessionAttributeName);
        }

        return authorizationRequest;
    }

    private String getStateParameter(HttpServletRequest request) {
        log.debug("getStateParameter called");
        return request.getParameter("state");
    }

    private OAuth2AuthorizationRequest getAuthorizationRequest(HttpServletRequest request) {
        log.debug("getAuthorizationRequest called");
        HttpSession session = request.getSession(false);
        return session != null ? (OAuth2AuthorizationRequest)session.getAttribute(this.sessionAttributeName) : null;
    }
}
