package com.example.spring.security.reference.commonsecurity;

public record SecurityErrorResponse(int status, String error, String message, String path) {
}
