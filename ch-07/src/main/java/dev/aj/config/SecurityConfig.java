package dev.aj.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity(prePostEnabled = true) //Instead of @EnableGlobalMethodSecurity, and default 'prePostEnabled' is true is can be left out
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.httpBasic(Customizer.withDefaults())
                           .authorizeHttpRequests(reqMatcherRegistery -> reqMatcherRegistery.anyRequest()
                                                                                        .authenticated())
                           .csrf(csrfCustomizer -> csrfCustomizer.ignoringRequestMatchers("/api/secure/*",
                                                                                          "/api/method/security/*",
                                                                                          "/api/method/security/filter/**"))
                           .build();
    }

    @Bean
    public UserDetailsService userDetailsService(@Qualifier("passwordEncoder") PasswordEncoder encoder) {
        UserDetails aj = User.withUsername("aj")
                             .password(encoder.encode("password"))
                             .authorities("read")
                             .build();

        UserDetails dj = User.withUsername("dj")
                             .password(encoder.encode("password"))
                             .authorities("write", "read")
                             .build();

        return new InMemoryUserDetailsManager(aj, dj);
    }


    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
