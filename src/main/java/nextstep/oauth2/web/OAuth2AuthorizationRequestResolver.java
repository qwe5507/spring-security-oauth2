package nextstep.oauth2.web;

import jakarta.servlet.http.HttpServletRequest;
import nextstep.oauth2.OAuth2ParameterNames;
import nextstep.oauth2.endpoint.OAuth2AuthorizationRequest;
import nextstep.oauth2.exception.OAuth2RegistrationNotFoundException;
import nextstep.oauth2.keygen.StateGenerator;
import nextstep.oauth2.registration.ClientRegistration;
import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.access.RequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

public class OAuth2AuthorizationRequestResolver {
    private static final StateGenerator DEFAULT_STATE_GENERATOR = new StateGenerator();
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final RequestMatcher requiresAuthenticationRequestMatcher;
    private final String authorizationRequestBaseUri;

    public OAuth2AuthorizationRequestResolver(final ClientRegistrationRepository clientRegistrationRepository,
                                              final String authorizationRequestBaseUri) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.requiresAuthenticationRequestMatcher = new MvcRequestMatcher(authorizationRequestBaseUri);
        this.authorizationRequestBaseUri = authorizationRequestBaseUri;
    }

    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        String registrationId = resolveRegistrationId(request);
        if (registrationId == null) {
            return null;
        }

        return resolve(registrationId);
    }

    private String resolveRegistrationId(final HttpServletRequest request) {
        if (requiresAuthenticationRequestMatcher.matches(request)) {
            return extractRegistrationId(request.getRequestURI(), authorizationRequestBaseUri);
        }

        return null;
    }

    public String extractRegistrationId(String requestUri, String baseUri) {
        if (requestUri.length() <= baseUri.length()) {
            throw new IllegalArgumentException("Invalid request URI: " + requestUri);
        }
        return requestUri.substring(baseUri.length());
    }

    private OAuth2AuthorizationRequest resolve(final String registrationId) {
        if (registrationId == null) {
            return null;
        }
        final ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);
        if (clientRegistration == null) {
            throw new OAuth2RegistrationNotFoundException(registrationId);
        }

        String state = DEFAULT_STATE_GENERATOR.generateState();
        return OAuth2AuthorizationRequest.builder()
                .authorizationUri(clientRegistration.getAuthorizationUri())
                .clientId(clientRegistration.getClientId())
                .redirectUri(clientRegistration.getRedirectUri())
                .scopes(clientRegistration.getScopes())
                .state(state)
                .authorizationRequestUri(buildAuthorizationRequestUri(clientRegistration, state))
                .attributes(Map.of(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId()))
                .build();
    }

    private String buildAuthorizationRequestUri(final ClientRegistration registration, String state) {
        final UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(registration.getAuthorizationUri());
        uriBuilder.queryParam("response_type", "code");
        uriBuilder.queryParam("client_id", registration.getClientId());
        uriBuilder.queryParam("scope", String.join(" ", registration.getScopes()));
        uriBuilder.queryParam("redirect_uri", registration.getRedirectUri());
        uriBuilder.queryParam("state", state);

        return uriBuilder.toUriString();
    }

}
