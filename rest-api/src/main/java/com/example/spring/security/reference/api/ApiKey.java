package com.example.spring.security.reference.api;

import java.util.List;

public record ApiKey(String name, List<String> roles, int quotaPerWindow, long windowSeconds) {
}
