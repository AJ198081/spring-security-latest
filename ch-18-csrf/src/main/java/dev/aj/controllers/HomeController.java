package dev.aj.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequestMapping(path = "/home")
public class HomeController {

    @RequestMapping(path = "/secure", method = RequestMethod.GET)
    public String getHome() {
        return "index";
    }

}
