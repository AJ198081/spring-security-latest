package dev.aj.secure.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api")
public class DemoController {

    @GetMapping(path = "/secure/{name}")
    public String sayHello(@PathVariable(name = "name") String name) {
        return String.format("Hello %s.", name);
    }

    @PostMapping(path = "/secure/{name}")
    public String postHello(@PathVariable(name = "name") String name) {
        return String.format("Hello %s.", name);
    }
}
