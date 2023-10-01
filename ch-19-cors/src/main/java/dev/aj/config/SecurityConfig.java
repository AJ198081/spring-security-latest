package dev.aj.config;

import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.authorizeHttpRequests(customizer -> customizer.anyRequest()
                                                                   .authenticated())
                    .httpBasic(Customizer.withDefaults());

        httpSecurity.cors(customizer -> {
            customizer.configurationSource(request -> {
                CorsConfiguration corsConfiguration = new CorsConfiguration();
                corsConfiguration.setAllowedOrigins(List.of("http://localhost:3006", "http://exmaple.com.au"));
                return corsConfiguration;
            });
        });

        return httpSecurity.build();
    }
}
