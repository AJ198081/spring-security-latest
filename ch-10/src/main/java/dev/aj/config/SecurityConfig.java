package dev.aj.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        return httpSecurity
                .httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests(customizer -> {
                                           customizer.requestMatchers("/api/security/*")
                                                     .authenticated();
                                           customizer.anyRequest()
                                                     .denyAll();
                                       }
                )
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService() {

        return new InMemoryUserDetailsManager(User.withUsername("aj")
                                                  .password("password")
                                                  .roles("admin", "user")
                                                  .build());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

}
