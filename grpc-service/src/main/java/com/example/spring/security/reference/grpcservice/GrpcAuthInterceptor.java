package com.example.spring.security.reference.grpcservice;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import org.springframework.stereotype.Component;

@Component
public class GrpcAuthInterceptor implements ServerInterceptor {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String VALID_TOKEN = "valid-token";

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call,
                                                                 Metadata headers,
                                                                 ServerCallHandler<ReqT, RespT> next) {
        String authorization = headers.get(Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER));

        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            call.close(Status.UNAUTHENTICATED.withDescription("Missing or invalid Authorization header"), new Metadata());
            return new ServerCall.Listener<>() {};
        }

        String token = authorization.substring(BEARER_PREFIX.length());
        if (!VALID_TOKEN.equals(token)) {
            call.close(Status.PERMISSION_DENIED.withDescription("Invalid bearer token"), new Metadata());
            return new ServerCall.Listener<>() {};
        }

        return next.startCall(call, headers);
    }
}
