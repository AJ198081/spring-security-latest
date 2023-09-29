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

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());    // Enable OpenID Connect 1.0

        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/login")))
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults()));

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

    //http://localhost:9098/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=https://www.manning.com/authorized&code_challenge=_JG2Kj9B-YBUWz7ir5j0VQDOMrDQFuKbiZbYrFawSAs&code_challenge_method=S256
    //http://localhost:9098/oauth2/token?grant_type=authorization_code&client_id=client&redirect_uri=https://www.manning.com/authorized&code=eA9m8UGNM4okp0Cq-W3fUkXKDbbDC0fJjg1ZMNS9DqbQbNexpMMqtIuOa-eGS8CLpPE75y-pLfwfVY9abL4PYkzffxIyKBmk7ybxZ07B8DSfplpPepf-NfWj9r9tUAhd&code_verifier=6hWMiuY5QnEu6A5ZJtLTwr85dalScHsUfCr08By1r7g
    @Bean // For Authorization_Code grant flow
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID()
                                                                  .toString())
                                                      .clientId("client")
                                                      .clientSecret("secret")
                                                      .clientAuthenticationMethod(
                                                              //How the authorization server expects the client to authenticate when sending requests for access tokens
                                                              ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                                                      .authorizationGrantType(
                                                              AuthorizationGrantType.AUTHORIZATION_CODE) //Grant type allowed by the authorization server for this client. A client might use multiple grant types.
                                                      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                                                      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                                                      .redirectUri(
                                                              "https://www.manning.com/authorized")
                                                      .postLogoutRedirectUri("http://127.0.0.1:9098/")
                                                      .scope(OidcScopes.OPENID)
                                                      .scope(OidcScopes.PROFILE)
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

        KeyPair keyPair;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey)
                                                     .keyID(UUID.randomUUID()
                                                                .toString())
                                                     .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean //Required to customise the 'end-points' that your Auth Server exposes as part of OIDC's /.well-known/oidc-configuration
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
