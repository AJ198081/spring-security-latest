package dev.aj.service;

import dev.aj.repositories.UserRepository;
import dev.aj.security.SecurityUser;
import java.util.NoSuchElementException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JpaUserDetailsService implements UserDetailsService {


    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findUserByUsername(username)
                             .map(SecurityUser::new)
                             .orElseThrow(() -> new NoSuchElementException(String.format("Unable to find username %s",
                                                                                         username)));
    }

}
