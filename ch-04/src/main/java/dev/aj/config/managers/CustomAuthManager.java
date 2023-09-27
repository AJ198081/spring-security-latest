package dev.aj.config.managers;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthManager implements AuthenticationManager {

    private final AuthenticationProvider authenticationProvider;

    public CustomAuthManager(@Qualifier("apiKeyAuthenticationProvider") AuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        if (authenticationProvider.supports(authentication.getClass())) {

            Authentication authenticationObject = authenticationProvider.authenticate(authentication);

            if (authenticationObject.isAuthenticated()) {
                SecurityContextHolder.getContext()
                                     .setAuthentication(authenticationObject);
                return authenticationObject;
            }
        }
        return null;
    }
}
