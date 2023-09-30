package dev.aj.repositories;

import dev.aj.entities.Client;
import java.util.Optional;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

public interface ClientRepository extends CrudRepository<Client, Long> {

    @Query("select c from Client c where c.clientId = :clientId")
    Optional<Client> findClientByClientId(@Param("clientId") String clientId);
}
