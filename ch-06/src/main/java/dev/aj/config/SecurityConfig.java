package dev.aj.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.httpBasic(Customizer.withDefaults())
                           .authorizeHttpRequests(authManagerReqMatcherRegistry -> {
                               authManagerReqMatcherRegistry.requestMatchers("/api/secure/*")
                                                            .hasAuthority("write");
                               authManagerReqMatcherRegistry.requestMatchers("/api/*/*")
                                                            .authenticated();
                           })
                .csrf(csrfConfigurer -> csrfConfigurer.ignoringRequestMatchers("/api/secure/**"))
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
