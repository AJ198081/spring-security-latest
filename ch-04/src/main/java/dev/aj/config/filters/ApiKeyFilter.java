package dev.aj.config.filters;

import dev.aj.config.authentications.ApiKeyAuthentication;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class ApiKeyFilter extends OncePerRequestFilter {

    String apiKey;

    private final AuthenticationManager authenticationManager;

    public ApiKeyFilter(@Value("${the.secret}") String apiKey, @Qualifier("customAuthManager") AuthenticationManager authenticationManager) {
        this.apiKey = apiKey;
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {


        var authentication = authenticationManager.authenticate(ApiKeyAuthentication.builder()
                                                                                    .isAuthenticated(false)
                                                                                    .apiKey(request.getHeader("Api_Key"))
                                                                                    .build());


        if (authentication.isAuthenticated()) {
            SecurityContextHolder.getContext()
                                 .setAuthentication(ApiKeyAuthentication.builder()
                                                                        .isAuthenticated(true)
                                                                        .build());
        }


        filterChain.doFilter(request, response);

    }
}
