package dev.aj.controllers;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api")
public class DemoController {

    @GetMapping(path = "/secure/{name}")
    @CrossOrigin(value = "http://example.com/")
    public String getDemo(@PathVariable String name) {
        return String.format("Hello %s", name);
    }

}
