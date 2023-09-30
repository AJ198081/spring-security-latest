package dev.aj.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
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
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain asSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);

        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                    .oidc(Customizer.withDefaults());

        httpSecurity.exceptionHandling(
                            exception -> exception.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                    .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));

        return httpSecurity.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(customizer -> customizer.anyRequest()
                                                           .authenticated())
            .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(User.withUsername("aj")
                                                  .password("password")
                                                  .roles("admin", "user")
                                                  .build());
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }


    //http://localhost:9012/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=https://springone.com/authorized
    //POST with clientId:ClientSecret -> http://localhost:9012/oauth2/token?grant_type=authorization_code&client_id=client&redirect_uri=https://www.springone.com/authorized&code=
//    @Bean
    RegisteredClientRepository registeredClientRepository() {
        return new InMemoryRegisteredClientRepository(RegisteredClient.withId(UUID.randomUUID()
                                                                                  .toString())
                                                                      .clientId("client")
                                                                      .clientSecret("secret")
                                                                      .clientAuthenticationMethod(
                                                                              ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                                                                      .authorizationGrantType(
                                                                              AuthorizationGrantType.AUTHORIZATION_CODE)
                                                                      .authorizationGrantType(
                                                                              AuthorizationGrantType.CLIENT_CREDENTIALS)
                                                                      .authorizationGrantType(
                                                                              AuthorizationGrantType.REFRESH_TOKEN)
                                                                      .redirectUri("https://springone.com/authorized")
                                                                      .postLogoutRedirectUri(
                                                                              "https://springone.com/loggedout")
                                                                      .scope(OidcScopes.OPENID)
                                                                      .scope(OidcScopes.PROFILE)
                                                                      .clientSettings(ClientSettings.builder()
                                                                                                    .requireProofKey(
                                                                                                            false)
                                                                                                    .requireAuthorizationConsent(
                                                                                                            true)
                                                                                                    .build())
                                                                      .tokenSettings(TokenSettings.builder()
                                                                                                  .accessTokenTimeToLive(
                                                                                                          Duration.ofHours(
                                                                                                                  2))
                                                                                                  .build())
                                                                      .build());
    }

    @Bean
    JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey)
                                                     .keyID(UUID.randomUUID()
                                                                .toString())
                                                     .build();

        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
        //Customise JWT's claims
    OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
        return context -> context.getClaims()
                                 .claim("token-name", "Aj's Customised Token Claim")
                                 .claim("email", "amarjitbhandal@gmail.com")
                                 .build();
    }

}
