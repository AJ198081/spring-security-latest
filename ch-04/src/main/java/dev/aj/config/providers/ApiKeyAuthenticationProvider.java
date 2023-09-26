package dev.aj.config.providers;

import dev.aj.config.authentications.ApiKeyAuthentication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class ApiKeyAuthenticationProvider implements AuthenticationProvider {

    @Value("${the.secret}")
    String apiKeySecret;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        ApiKeyAuthentication authenticationObject = (ApiKeyAuthentication) authentication;

        if (authenticationObject.getApiKey().equals(apiKeySecret)) {
            authentication.setAuthenticated(true);
            return authentication;
        }

        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ApiKeyAuthentication.class.isAssignableFrom(authentication);
    }
}
