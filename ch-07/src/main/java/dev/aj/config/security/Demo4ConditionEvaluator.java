package dev.aj.config.security;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class Demo4ConditionEvaluator {


    public boolean evaluation(@NonNull String name) {
        Authentication authentication = SecurityContextHolder.getContext()
                                                             .getAuthentication();
        if (authentication instanceof UsernamePasswordAuthenticationToken userDetails) {
            return userDetails.getName()
                              .contains(String.valueOf(name.charAt(name.length() - 1)).toLowerCase());
        }

        return false;
    }

}
