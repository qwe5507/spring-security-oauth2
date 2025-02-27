package nextstep.oauth2.endpoint;

import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class OAuth2AuthorizationRequest {
    private final String authorizationUri;
    private final String clientId;
    private final String redirectUri;
    private final Set<String> scopes;
    private final String state;
    private final String authorizationRequestUri;
    private final Map<String, Object> attributes;

    private OAuth2AuthorizationRequest(Builder builder) {
        this.authorizationUri = builder.authorizationUri;
        this.clientId = builder.clientId;
        this.redirectUri = builder.redirectUri;
        this.scopes = builder.scopes;
        this.state = builder.state;
        this.authorizationRequestUri = builder.authorizationRequestUri;
        this.attributes = Collections.unmodifiableMap(builder.attributes);
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getAuthorizationUri() {
        return authorizationUri;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public String getState() {
        return state;
    }

    public String getAuthorizationRequestUri() {
        return authorizationRequestUri;
    }

    public String getAttribute(String key) {
        return (String) attributes.get(key);
    }

    public static class Builder {
        private String authorizationUri;
        private String clientId;
        private String redirectUri;
        private Set<String> scopes;
        private String state;
        private String authorizationRequestUri;
        private Map<String, Object> attributes = new LinkedHashMap<>();

        public Builder authorizationUri(String authorizationUri) {
            this.authorizationUri = authorizationUri;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder scopes(Set<String> scopes) {
            this.scopes = scopes;
            return this;
        }

        public Builder state(String state) {
            this.state = state;
            return this;
        }

        public Builder authorizationRequestUri(String authorizationRequestUri) {
            this.authorizationRequestUri = authorizationRequestUri;
            return this;
        }

        public Builder attributes(Map<String, Object> attributes) {
            if (!CollectionUtils.isEmpty(attributes)) {
                this.attributes.putAll(attributes);
            }
            return this;
        }

        public OAuth2AuthorizationRequest build() {
            return new OAuth2AuthorizationRequest(this);
        }
    }
}
