package dev.aj.config;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.oauth2ResourceServer(customizer -> {
            customizer.authenticationManagerResolver(authenticationManagerResolver());
        });

        httpSecurity.authorizeHttpRequests(customizer -> customizer.anyRequest()
                                                                   .authenticated());
        return httpSecurity.build();
    }

    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
        var authenticationManager = new JwtIssuerAuthenticationManagerResolver(
                List.of("http://localhost:9012", "http://localhost:9017"));
        return authenticationManager;
    }
}
