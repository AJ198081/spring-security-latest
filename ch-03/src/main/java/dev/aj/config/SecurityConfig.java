package dev.aj.config;

import dev.aj.config.filters.CustomUsernamePasswordFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, CustomUsernamePasswordFilter filter,
                                                   AuthenticationManager authenticationManager) throws Exception {

        return httpSecurity.addFilterAt(filter, UsernamePasswordAuthenticationFilter.class)
                           .authorizeHttpRequests(customizer -> customizer.anyRequest()
                                                                          .authenticated()
//                                                                          .requestMatchers("/admin/**")
//                                                                          .hasRole("ADMIN")
//                                                                          .requestMatchers("/**")
//                                                                          .hasAuthority("READ")
                           )
                           .authenticationManager(authenticationManager)
                           .build();
    }

}
