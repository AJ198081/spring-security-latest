package dev.aj.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api")
public class DemoController {

    @GetMapping("/secure/{name}")
    public String getName(@PathVariable(name = "name") String name) {
        return String.format("Hello %s.", name);
    }
}
