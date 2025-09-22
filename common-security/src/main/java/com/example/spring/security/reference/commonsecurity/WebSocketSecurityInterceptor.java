package com.example.spring.security.reference.commonsecurity;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.stereotype.Component;

/**
 * Example WebSocket channel interceptor for authentication/authorization.
 */
@Component
public class WebSocketSecurityInterceptor implements ChannelInterceptor {
    @Override
    public Message<?> preSend(Message<?> message, MessageChannel channel) {
        // Example: Check authentication, validate JWT or session
        // For demonstration, allow all messages
        return message;
    }
}