package com.spring_security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping("/api/user/info")
    public String getUserInfo(Authentication authentication) {
        return "User: " + authentication.getName() + " - Roles: " + authentication.getAuthorities();
    }

    @GetMapping("/api/public")
    public String publicEndpoint() {
        return "This is a public endpoint";
    }
}