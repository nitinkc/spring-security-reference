package com.example.spring.security.reference.commonsecurity;

import io.grpc.*;
import org.springframework.stereotype.Component;

/**
 * Example gRPC server interceptor for authentication/authorization.
 */
@Component
public class GrpcSecurityInterceptor implements ServerInterceptor {
    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        // Example: Validate JWT from metadata headers
        String jwt = headers.get(Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER));
        if (jwt == null || !jwt.startsWith("Bearer ")) {
            call.close(Status.UNAUTHENTICATED.withDescription("Missing JWT"), headers);
            return new ServerCall.Listener<>() {};
        }
        // Add more validation as needed
        return next.startCall(call, headers);
    }
}