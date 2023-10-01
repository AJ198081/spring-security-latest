package dev.aj.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

@Entity
@Table(name = "client")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
@Builder
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String clientId;
    private String secret;
    private String scope;
    private String authMethod;
    private String grantType;
    @Column(name = "redirect_ui")
    private String redirectUri;

    public static Client fromRegisteredClient(RegisteredClient registeredClient) {
        return Client.builder()
                     .clientId(registeredClient.getClientId())
                     .secret(registeredClient.getClientSecret())
                     .scope(registeredClient.getScopes()
                                            .stream()
                                            .collect(Collectors.joining(",")))
                     .authMethod(registeredClient.getClientAuthenticationMethods()
                                                 .stream()
                                                 .map(Object::toString)
                                                 .collect(Collectors.joining(",")))
                     .grantType(registeredClient.getAuthorizationGrantTypes()
                                                .stream()
                                                .map(Object::toString)
                                                .collect(Collectors.joining(",")))
                     .redirectUri(String.join(",", registeredClient.getRedirectUris()))

                     .build();
    }

    public static RegisteredClient toRegisteredClient(Client client) {
        return RegisteredClient.withId(String.valueOf(client.id))
                               .clientId(client.clientId)
                               .clientSecret(client.secret)
                               .scope(client.scope)
                               .clientAuthenticationMethods(consumer -> {
                                            Arrays.stream(client.authMethod.split(","))
                                                  .map(ClientAuthenticationMethod::new)
                                                  .forEach(consumer::add);
                                        })
                               .authorizationGrantTypes(consumer ->
                                                                         Arrays.stream(client.grantType.split(","))
                                                                               .map(AuthorizationGrantType::new)
                                                                               .forEach(consumer::add))
                               .redirectUris(consumer ->
                                                              consumer.addAll(List.of(client.redirectUri.split(","))))
                               .clientSettings(ClientSettings.builder()
                                                                      .requireProofKey(false)
                                                                      .requireAuthorizationConsent(false)
                                                                      .build())
                               .tokenSettings(TokenSettings.builder()
                                                                    .accessTokenTimeToLive(Duration.ofHours(1))
                                                                    .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                                                                    .build())
                               .build();
    }


}
