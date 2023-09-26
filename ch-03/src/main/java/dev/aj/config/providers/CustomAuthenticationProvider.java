package dev.aj.config.providers;

import dev.aj.config.authentications.CustomAuthenticationObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Value("${custom.security.key}")
    private String securityKey;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        CustomAuthenticationObject authenticationObject = (CustomAuthenticationObject) authentication;


        if (authenticationObject.getAuthenticationKey()
                                .equals(securityKey)) {

            authenticationObject.setAuthenticated(true);

            return authenticationObject;
        } else {
            return null;
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomAuthenticationObject.class
                .isAssignableFrom(authentication);
    }
}
