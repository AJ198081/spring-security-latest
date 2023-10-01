package dev.aj.simple.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.oauth2ResourceServer(customizer -> {
            customizer.jwt(
                    jwtConfigurer -> jwtConfigurer.jwkSetUri("http://localhost:9012/jwks")
            );
        });

        httpSecurity.authorizeHttpRequests(request -> request.anyRequest()
                                                             .authenticated());

        return httpSecurity.build();
    }

}
