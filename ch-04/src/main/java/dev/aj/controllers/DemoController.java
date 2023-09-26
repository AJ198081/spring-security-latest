package dev.aj.controllers;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api")
public class DemoController {

    @GetMapping("/security/{name}")
    public String getHello(@PathVariable String name) {

        SecurityContextHolder.getContext().getAuthentication();

        return String.format("Hello %s",
                             name);
    }

}