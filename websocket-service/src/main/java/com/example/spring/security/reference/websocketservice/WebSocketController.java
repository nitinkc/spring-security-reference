package com.example.spring.security.reference.websocketservice;

import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.stereotype.Controller;

@Controller
public class WebSocketController {
    @MessageMapping("/hello")
    @SendTo("/topic/greetings")
    public String greet(String message) {
        // Simple echo for demonstration
        return "Hello, " + message + "!";
    }
}
