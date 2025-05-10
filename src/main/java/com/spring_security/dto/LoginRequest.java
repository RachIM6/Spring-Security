package com.spring_security.dto;

public record LoginRequest(
        String username,
        String password
) {}