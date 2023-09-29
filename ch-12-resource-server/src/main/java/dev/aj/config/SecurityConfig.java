package dev.aj.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // {facebook.com}/.well-known/openid-configuration is the end-point that all OIDC providers expose, part of 'OIDC' standardisation effort
    @Value(value = "${authorization.server.jwk.uri: http://localhost:9012/oauth2/jwks}")
    private String jwkUri;

    @Bean
    SecurityFilterChain rsSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.oauth2ResourceServer(
                customizer -> customizer.jwt(jwtConfigurer -> jwtConfigurer.jwkSetUri(jwkUri)));

        httpSecurity.authorizeHttpRequests(customizer -> customizer.anyRequest()
                                                                   .authenticated());
        return httpSecurity.build();
    }

}
