package dev.aj.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class DemoController {

    private final OAuth2AuthorizedClientManager authorizedClientManager;

    @GetMapping("/secure/{name}")
    public String getDemoText(@PathVariable(name = "name") String name) {

        OAuth2AuthorizedClient oAuth2AuthorizedClient = authorizedClientManager.authorize(
                OAuth2AuthorizeRequest.withClientRegistrationId("1")
                                      .principal("client")
                                      .build());

        return String.format("Hello %s, Access Token: %s.", name, oAuth2AuthorizedClient.getAccessToken().getTokenValue());
    }
}
