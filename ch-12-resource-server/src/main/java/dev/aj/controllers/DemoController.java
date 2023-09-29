package dev.aj.controllers;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api")
public class DemoController {

    @GetMapping(path = "/security/{name}")
    public String resourceServerSecurity(@PathVariable String name) {

         JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) SecurityContextHolder.getContext()
                                                                                               .getAuthentication();

        Jwt principal = (Jwt) jwtAuthenticationToken.getPrincipal();

        return String.format("Hello %s", principal.getClaims().get("email"));
    }


}
