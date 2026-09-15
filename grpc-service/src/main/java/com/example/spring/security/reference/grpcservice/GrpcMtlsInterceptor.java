package com.example.spring.security.reference.grpcservice;

import io.grpc.Attributes;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

@Component
public class GrpcMtlsInterceptor implements ServerInterceptor {

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call,
                                                                 Metadata headers,
                                                                 ServerCallHandler<ReqT, RespT> next) {
        Attributes attributes = call.getAttributes();
        SSLSession session = attributes.get(Grpc.TRANSPORT_ATTR_SSL_SESSION);

        if (session == null) {
            call.close(Status.UNAUTHENTICATED.withDescription("mTLS session required"), new Metadata());
            return new ServerCall.Listener<>() {};
        }

        try {
            Certificate[] certs = session.getPeerCertificates();
            if (certs.length == 0 || !(certs[0] instanceof X509Certificate x509)) {
                call.close(Status.UNAUTHENTICATED.withDescription("No peer certificate"), new Metadata());
                return new ServerCall.Listener<>() {};
            }

            X500Principal principal = x509.getSubjectX500Principal();
            String cn = extractCn(principal.getName());
            if (cn.isBlank()) {
                call.close(Status.UNAUTHENTICATED.withDescription("Client certificate has no CN"), new Metadata());
                return new ServerCall.Listener<>() {};
            }

            return next.startCall(call, headers);
        } catch (Exception exception) {
            call.close(Status.UNAUTHENTICATED.withDescription("Could not validate peer certificate"), new Metadata());
            return new ServerCall.Listener<>() {};
        }
    }

    private String extractCn(String name) {
        for (String part : name.split(",")) {
            String trimmed = part.trim();
            if (trimmed.toLowerCase().startsWith("cn=")) {
                return trimmed.substring(3).trim();
            }
        }
        return "";
    }
}
