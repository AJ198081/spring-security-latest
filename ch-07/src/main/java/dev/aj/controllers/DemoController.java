package dev.aj.controllers;

import java.util.List;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api")
public class DemoController {

    @GetMapping("/security/{name}")
//    @PreAuthorize("hasAnyAuthority('read', 'write')")
    @PreAuthorize("""
            (#name.toLowerCase() == authentication.name) or
            hasAuthority('write')
            """)
    public String getHello(@PathVariable String name) {

        SecurityContextHolder.getContext()
                             .getAuthentication();

        return String.format("Hello %s", name);
    }

    @PostMapping("/secure/{name}")
    @PreAuthorize("hasAuthority('write')")
    public String postHello(@PathVariable String name) {
        Authentication authentication = SecurityContextHolder.getContext()
                                                             .getAuthentication();

        return String.format("Hello name: %s, Principal: %s", name, authentication.getPrincipal());
    }

    @PostMapping("/method/security/{name}")
    @PreAuthorize("@demo4ConditionEvaluator.evaluation((#name))")
    @PostAuthorize("returnObject == 'aj'")
    public String getPrincipal(@PathVariable String name) {
        String returnedObject = SecurityContextHolder.getContext()
                                                     .getAuthentication()
                                                     .getName();
        return returnedObject;
    }

    @PostMapping("/method/security/filter/{name}")
    @PreFilter(value = "filterObject.contains('J')", filterTarget = "bodyList")
    public String filterRequestObjects(@PathVariable String name, @RequestBody List<String> bodyList) {

        bodyList.forEach(System.out::println);

        String returnedObject = SecurityContextHolder.getContext()
                                                     .getAuthentication()
                                                     .getName();
        return returnedObject;
    }

    @PostMapping("/method/security/filter/post/{name}")
    @PostFilter(value = "filterObject.contains('J')")
    public List<String> filterResponseObjects(@PathVariable String name, @RequestBody List<String> bodyList) {
        return bodyList;
    }


}