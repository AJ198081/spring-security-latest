package dev.aj.repositories;

import dev.aj.domain.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository // even though doesn't actually do anything, instances are only created from concrete implementations, not interfaces
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findUserByUsername(String userName);
}
