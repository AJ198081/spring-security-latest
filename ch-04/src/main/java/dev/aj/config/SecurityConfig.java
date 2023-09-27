package dev.aj.config;

import dev.aj.config.filters.ApiKeyFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final ApiKeyFilter apiKeyFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        return httpSecurity.httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests(customiser -> customiser.requestMatchers("/**").authenticated())
                           .addFilterBefore(apiKeyFilter, BasicAuthenticationFilter.class)
                           .build();
    }
}
