package dev.aj.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.firewall.StrictHttpFirewall;

@Configuration
@EnableWebSecurity
public class AuthServerConfig {

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());    // Enable OpenID Connect 1.0

        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/login")));
        // Accept access tokens for User Info and/or Client Registration
//                .oauth2ResourceServer((resourceServer) -> resourceServer
//                        .jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(authorize -> authorize.anyRequest()
                                                           .authenticated())
            .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withUsername("aj")
                                      .password("password")
                                      .roles("USER")
                                      .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    //http://localhost:9098/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=https://www.manning.com/authorized&code_challenge=slI6GHmAJ4Bb0ydSJRqioS6LFUc_-dD_wOifj9I51T0&code_challenge_method=S256
    //http://localhost:9098/oauth2/token?grant_type=authorization_code&client_id=client&redirect_uri=https://www.manning.com/authorized&code=K5T13yStgXaDJLoASE6i4gBHW1w4pv_85ivRKE0UFDAgLJUpr62mH-w38pk6hUa7ClgrBtBLejroZgC9A4fzDq8UAzJykZkmMZzIfRuWqLENc4wN6Qs_XJxfahT30lQU&code_verifier=dUWsTRTw9gIq3vWL1G89F41HW2gd3Va7UvKDjgrWgy8
    @Bean // For Authorization_Code grant flow
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID()
                                                                  .toString())
                                                      .clientId("client")
                                                      .clientSecret("secret")
                                                      .clientAuthenticationMethod( //How the authorization server expects the client to authenticate when sending requests for access tokens
                                                              ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                                                      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) //Grant type allowed by the authorization server for this client. A client might use multiple grant types.
//                                                      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                                                      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                                                      .redirectUri(
                                                              "https://www.manning.com/authorized")
                                                      .postLogoutRedirectUri("http://127.0.0.1:9098/")
//                                                      .scope(OidcScopes.OPENID)
                                                      .scope(OidcScopes.OPENID)
                                                      .clientSettings(ClientSettings.builder()
                                                                                    .requireAuthorizationConsent(true)
                                                                                    .requireProofKey(true)
                                                                                    .build())
                                                      .build();

        return new InMemoryRegisteredClientRepository(oidcClient);
    }

    // http://localhost:9098/oauth2/token?grant_type=client_credentials&scope=openid
    // Authorization: client:secret (BASE64 encoded, ctrl + alt + 6)
//    @Bean // For client_credentials grant flow
    public RegisteredClientRepository registeredClientRepositoryClientCredentials() {

        return new InMemoryRegisteredClientRepository(RegisteredClient.withId(UUID.randomUUID()
                                                                                  .toString())
                                                                      .clientId("client")
                                                                      .clientSecret("secret")
                                                                      .clientAuthenticationMethod(
                                                                              ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                                                                      .authorizationGrantType(
                                                                              AuthorizationGrantType.CLIENT_CREDENTIALS)
                                                                      .redirectUri("http://localhost:9098/authorized")
                                                                      .postLogoutRedirectUri(
                                                                              "http://localhost:9098/logged/out")
                                                                      .scope(OidcScopes.OPENID)
                                                                      .build());

    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey)
                                                     .keyID(UUID.randomUUID()
                                                                .toString())
                                                     .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    //    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                                          .build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowSemicolon(true);
        return web -> web.httpFirewall(firewall);
    }

}
