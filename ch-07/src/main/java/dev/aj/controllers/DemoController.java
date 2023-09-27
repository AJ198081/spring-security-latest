package dev.aj.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api")
public class DemoController {

    @GetMapping("/security/{name}")
    @PreAuthorize("hasAnyAuthority('read', 'write')")
    public String getHello(@PathVariable String name) {

        SecurityContextHolder.getContext()
                             .getAuthentication();

        return String.format("Hello %s",
                             name);
    }

    @PostMapping("/secure/{name}")
    @PreAuthorize("hasAuthority('write')")
    public String postHello(@PathVariable String name) {
        Authentication authentication = SecurityContextHolder.getContext()
                                                             .getAuthentication();

        return String.format("Hello name: %s, Principal: %s", name, authentication.getPrincipal());
    }
}