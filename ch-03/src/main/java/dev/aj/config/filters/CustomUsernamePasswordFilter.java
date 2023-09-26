package dev.aj.config.filters;

import dev.aj.config.authentications.CustomAuthenticationObject;
import dev.aj.config.managers.CustomAuthenticationManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class CustomUsernamePasswordFilter extends OncePerRequestFilter {

    private final CustomAuthenticationManager authenticationManager;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authenticationKey = request.getHeader("Authentication_Key");

        CustomAuthenticationObject authenticationObject = CustomAuthenticationObject.builder()
                                                                     .isAuthenticated(false)
                                                                     .authenticationKey(authenticationKey)
                                                                     .build();

        Authentication authentication = authenticationManager.authenticate(authenticationObject);

        if (Objects.nonNull(authentication) && authentication.isAuthenticated()) {
            SecurityContextHolder.getContext()
                                 .setAuthentication(authentication);

        }

        filterChain.doFilter(request,
                             response);
    }
}
