package dev.aj.simple.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class DemoController {

    @GetMapping(path = "/secure/{name}")
    public String getDemo(@PathVariable String name) {
        return "Hello " + name;
    }

    @PostMapping(path = "/secure/{name}")
    public String postDemo(@PathVariable String name) {
        return "Hello " + name;
    }
}
