package dev.aj.services;

import dev.aj.entities.Client;
import dev.aj.repositories.ClientRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Transactional
public class CustomClientService implements RegisteredClientRepository {

    private final ClientRepository clientRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        clientRepository.save(Client.fromRegisteredClient(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        RegisteredClient registeredClient = Client.toRegisteredClient(clientRepository.findById(Long.valueOf(id))
                                                                                      .orElseThrow());
        return registeredClient;
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {

        RegisteredClient registeredClient = Client.toRegisteredClient(clientRepository.findClientByClientId(clientId)
                                                                                      .orElseThrow(
                                                                                              () -> new UsernameNotFoundException(
                                                                                                      String.format(
                                                                                                              "Unable to find client-id: %s, in database.",
                                                                                                              clientId))));
        return registeredClient;
    }

}
