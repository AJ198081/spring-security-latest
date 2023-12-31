package dev.aj.services;

import dev.aj.entities.dtos.CustomUserDetails;
import dev.aj.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findUserByUsername(username)
                             .map(CustomUserDetails::new)
                             .orElseThrow(() -> new UsernameNotFoundException(
                                     String.format("Unable to find user: %s, in database", username)));
    }
}
