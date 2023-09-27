package dev.aj.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        return httpSecurity.httpBasic(Customizer.withDefaults())
                           .authorizeHttpRequests(customizer -> {
                               customizer.requestMatchers(HttpMethod.GET, "/api/security/**")
                                         .hasAuthority("write");
                               customizer.requestMatchers(HttpMethod.POST, "/api/secure/**")
                                         .hasAuthority("write");
                               customizer.anyRequest()
                                         .denyAll();
                           })
                           .csrf(csrfConfigurer -> csrfConfigurer.ignoringRequestMatchers("/api/secure/**"))
                           .build();
    }

    @Bean
    public UserDetailsService userDetailsService(@Qualifier("encoder") PasswordEncoder encoder) {

        UserDetails aj = User.withUsername("aj")
                                .password(passwordEncoder().encode("password"))
                                .authorities("read")
                                .build();

        UserDetails dj = User.withUsername("dj")
                                .password(passwordEncoder().encode("password"))
                                .authorities("write", "read")
                                .build();

        return new InMemoryUserDetailsManager(aj, dj);
    }

    @Bean(name = "encoder")
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
