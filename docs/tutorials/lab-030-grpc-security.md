# LAB-030: gRPC Security

## Status

- Theory prerequisite: `docs/theory/grpc-security.md`
- Implementation: `grpc-service` module
- Tests: `GrpcSecurityLabTest`
- Verification: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :grpc-service:test --tests '*GrpcSecurityLabTest'`

## Measurable objective

Implement `ServerInterceptor` logic for gRPC bearer-token metadata and mTLS peer-certificate identity. Tests must prove the interceptors reject missing/invalid tokens and missing/invalid client certificates before the service handler runs.

## Source artifact map

| File | Purpose |
|---|---|
| `GrpcAuthInterceptor.java` | Reads `Authorization` metadata, validates `Bearer valid-token`, rejects invalid calls |
| `GrpcMtlsInterceptor.java` | Extracts peer `X509Certificate` from the TLS `SSLSession`, parses the `CN`, rejects missing certs |
| `GrpcSecurityLabTest.java` | Mockito tests for token and mTLS interceptor behavior |

## Exercises

1. Review `GrpcAuthInterceptor` and identify why `call.close` is called before the service handler is invoked.
2. Trace how `GrpcMtlsInterceptor` obtains the client certificate from the gRPC transport attributes.
3. Run `GrpcSecurityLabTest` and explain why a missing `Authorization` header returns `UNAUTHENTICATED` while a wrong token returns `PERMISSION_DENIED`.
4. Identify the production changes needed to attach these interceptors to a real `NettyServerBuilder` with TLS.

## Commands

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :grpc-service:test --tests '*GrpcSecurityLabTest'
```

## Positive and negative test expectations

| Scenario | Expected |
|---|---|
| Missing `Authorization` metadata | `call.close(Status.UNAUTHENTICATED)` |
| `Bearer wrong-token` | `call.close(Status.PERMISSION_DENIED)` |
| `Bearer valid-token` | `next.startCall` invoked |
| No TLS `SSLSession` in attributes | `call.close(Status.UNAUTHENTICATED)` |
| Valid client certificate with `CN=client` | `next.startCall` invoked |

## Production extension

- Wire `GrpcAuthInterceptor` and `GrpcMtlsInterceptor` into a `NettyServerBuilder` for a real service.
- Configure `SslContext` with a trust manager that validates client certificates against a CA.
- Replace the hardcoded `valid-token` with a JWT or token-introspection check.
- Map the extracted `CN` to a Spring Security `Authentication` and use `AuthorizationManager` for method-level checks.
- Add request-id metadata and redacted logging for gRPC calls.

## Completion evidence

```text
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :grpc-service:test --tests '*GrpcSecurityLabTest'
BUILD SUCCESSFUL
GrpcSecurityLabTest: 5 passed
```

## Next lab

LAB-031 — WebSocket Security.
