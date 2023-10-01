package dev.aj.entities.dtos;

import dev.aj.entities.User;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    private final User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(user.getAuthorities()));
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return Objects.nonNull(user);
    }

    @Override
    public boolean isAccountNonLocked() {
        return Objects.nonNull(user);
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return Objects.nonNull(user);
    }

    @Override
    public boolean isEnabled() {
        return Objects.nonNull(user);
    }
}
