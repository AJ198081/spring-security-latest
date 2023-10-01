package dev.aj.repositories;

import dev.aj.entities.User;
import java.util.Optional;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<User, Long> {

    Optional<User> findUserByUsername(String username);

}
