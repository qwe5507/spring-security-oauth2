package nextstep.oauth2.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.oauth2.OAuth2AuthorizationResponseUtils;
import nextstep.oauth2.OAuth2AuthorizedClient;
import nextstep.oauth2.OAuth2ParameterNames;
import nextstep.oauth2.authentication.OAuth2AuthenticationToken;
import nextstep.oauth2.authentication.OAuth2LoginAuthenticationToken;
import nextstep.oauth2.endpoint.OAuth2AuthorizationExchange;
import nextstep.oauth2.endpoint.OAuth2AuthorizationRequest;
import nextstep.oauth2.endpoint.OAuth2AuthorizationResponse;
import nextstep.oauth2.exception.OAuth2AuthenticationException;
import nextstep.oauth2.registration.ClientRegistration;
import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.access.RequestMatcher;
import nextstep.security.authentication.AbstractAuthenticationProcessingFilter;
import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationException;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.context.HttpSessionSecurityContextRepository;
import nextstep.security.context.SecurityContext;
import nextstep.security.context.SecurityContextHolder;
import org.springframework.core.convert.converter.Converter;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;

import java.io.IOException;

public class OAuth2LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private static final String DEFAULT_FILTER_PROCESSES_URI = "/login/oauth2/code/";
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository = new OAuth2AuthorizedClientRepository();
    private final AuthorizationRequestRepository authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();

    private final RequestMatcher requestMatcherrequiresAuthenticationRequestMatcher = new MvcRequestMatcher(DEFAULT_FILTER_PROCESSES_URI);
    private final HttpSessionSecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private Converter<OAuth2LoginAuthenticationToken, OAuth2AuthenticationToken> authenticationResultConverter = this::createAuthenticationResult;

    public OAuth2LoginAuthenticationFilter(final ClientRegistrationRepository clientRegistrationRepository, AuthenticationManager authenticationManager) {
        super(authenticationManager);
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    protected boolean requiresAuthentication(final HttpServletRequest request, final HttpServletResponse response) {
        return requestMatcherrequiresAuthenticationRequestMatcher.matches(request);
    }

    @Override
    protected Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        OAuth2AuthorizationRequest authorizationRequest = getAuthorizationRequest(request, response);

        String registrationId = authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
        ClientRegistration clientRegistration = getClientRegistration(registrationId);

        OAuth2AuthorizationResponse authorizationResponse = getOAuth2AuthorizationResponse(request, clientRegistration);

        OAuth2LoginAuthenticationToken authenticationRequest = OAuth2LoginAuthenticationToken.unauthenticated(clientRegistration,
                new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));

        OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken) authenticationManager
                .authenticate(authenticationRequest);

        OAuth2AuthenticationToken oauth2Authentication = this.authenticationResultConverter.convert(authenticationResult);
        Assert.notNull(oauth2Authentication, "authentication result cannot be null");

        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                authenticationResult.getClientRegistration(), oauth2Authentication.principalName(), authenticationResult.getAccessToken());

        this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, oauth2Authentication, request, response);

        return oauth2Authentication;
    }

    private OAuth2AuthorizationResponse getOAuth2AuthorizationResponse(final HttpServletRequest request, final ClientRegistration clientRegistration) {
        MultiValueMap<String, String> params = OAuth2AuthorizationResponseUtils.toMultiMap(request.getParameterMap());
        if (!OAuth2AuthorizationResponseUtils.isAuthorizationResponse(params)) {
            throw new OAuth2AuthenticationException();
        }

        OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponseUtils.convert(params,
                clientRegistration.getRedirectUri());
        return authorizationResponse;
    }

    private OAuth2AuthorizationRequest getAuthorizationRequest(final HttpServletRequest request, final HttpServletResponse response) {
        OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.removeAuthorizationRequest(request, response);
        if (authorizationRequest == null) {
            throw new OAuth2AuthenticationException();
        }
        return authorizationRequest;
    }

    private ClientRegistration getClientRegistration(final String registrationId) {
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
        if (clientRegistration == null) {
            throw new OAuth2AuthenticationException();
        }
        return clientRegistration;
    }

    public String extractRegistrationId(String requestUri) {
        if (requestUri.length() <= DEFAULT_FILTER_PROCESSES_URI.length()) {
            throw new IllegalArgumentException("Invalid request URI: " + requestUri);
        }
        return requestUri.substring(DEFAULT_FILTER_PROCESSES_URI.length());
    }

    private OAuth2AuthenticationToken createAuthenticationResult(OAuth2LoginAuthenticationToken authenticationResult) {
        return OAuth2AuthenticationToken.success(authenticationResult.getPrincipal(), authenticationResult.getAuthorities());
    }

    @Override
    protected void successfulAuthentication(final HttpServletRequest request, final HttpServletResponse response, final FilterChain chain, final Authentication authenticationResult) throws AuthenticationException, IOException, ServletException {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authenticationResult);
        SecurityContextHolder.setContext(context);
        this.securityContextRepository.saveContext(context, request, response);

        response.sendRedirect("/");
    }
}
