package com.example.spring.security.reference.grpcservice;

import io.grpc.Attributes;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.Status;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class GrpcSecurityLabTest {

    private final GrpcAuthInterceptor authInterceptor = new GrpcAuthInterceptor();
    private final GrpcMtlsInterceptor mtlsInterceptor = new GrpcMtlsInterceptor();

    @SuppressWarnings("unchecked")
    private final ServerCall<Object, Object> call = mock(ServerCall.class);

    @SuppressWarnings("unchecked")
    private final ServerCallHandler<Object, Object> next = mock(ServerCallHandler.class);

    @Test
    void missingAuthorizationHeaderIsUnauthenticated() {
        authInterceptor.interceptCall(call, new Metadata(), next);

        ArgumentCaptor<Status> statusCaptor = ArgumentCaptor.forClass(Status.class);
        verify(call).close(statusCaptor.capture(), any(Metadata.class));
        assertEquals(Status.Code.UNAUTHENTICATED, statusCaptor.getValue().getCode());
        verify(next, never()).startCall(any(), any());
    }

    @Test
    void invalidTokenIsPermissionDenied() {
        Metadata headers = new Metadata();
        headers.put(Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer wrong-token");

        authInterceptor.interceptCall(call, headers, next);

        ArgumentCaptor<Status> statusCaptor = ArgumentCaptor.forClass(Status.class);
        verify(call).close(statusCaptor.capture(), any(Metadata.class));
        assertEquals(Status.Code.PERMISSION_DENIED, statusCaptor.getValue().getCode());
        verify(next, never()).startCall(any(), any());
    }

    @Test
    void validTokenProceeds() {
        Metadata headers = new Metadata();
        headers.put(Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer valid-token");

        authInterceptor.interceptCall(call, headers, next);

        verify(call, never()).close(any(), any());
        verify(next).startCall(any(), any());
    }

    @Test
    void missingMtlsSessionIsUnauthenticated() {
        when(call.getAttributes()).thenReturn(Attributes.EMPTY);

        mtlsInterceptor.interceptCall(call, new Metadata(), next);

        ArgumentCaptor<Status> statusCaptor = ArgumentCaptor.forClass(Status.class);
        verify(call).close(statusCaptor.capture(), any(Metadata.class));
        assertEquals(Status.Code.UNAUTHENTICATED, statusCaptor.getValue().getCode());
        verify(next, never()).startCall(any(), any());
    }

    @Test
    void validClientCertificateProceeds() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal("CN=client, O=example"));

        SSLSession session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenReturn(new Certificate[]{cert});

        Attributes attributes = Attributes.newBuilder()
                .set(Grpc.TRANSPORT_ATTR_SSL_SESSION, session)
                .build();
        when(call.getAttributes()).thenReturn(attributes);

        mtlsInterceptor.interceptCall(call, new Metadata(), next);

        verify(call, never()).close(any(), any());
        verify(next).startCall(any(), any());
    }
}
