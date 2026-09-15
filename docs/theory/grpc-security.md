# gRPC Security

gRPC runs over HTTP/2 and uses Protobuf. Security must cover the transport (mTLS or channel credentials), the metadata (bearer tokens and other per-call headers), and the call itself.

## Security objective

Demonstrate bearer-token authentication from gRPC `Metadata` and mutual-TLS peer identity extraction from the transport `SSLSession`, both as `ServerInterceptor` logic that can be attached to any gRPC service.

## Core concepts

| Term | Meaning |
|---|---|
| **ServerInterceptor** | A gRPC server-side interceptor that can inspect and reject a call before it reaches the service implementation. |
| **Metadata** | gRPC per-call headers, commonly carrying `Authorization` and other request-scoped values. |
| **mTLS** | Transport-layer mutual TLS where the client presents an X.509 certificate and the server verifies it. |
| **SSLSession** | The Java TLS session containing the peer certificate chain, accessible from `Grpc.TRANSPORT_ATTR_SSL_SESSION`. |
| **Peer CN** | The common name from the client certificate's subject, used as a transport-level identity. |

## Trust boundaries

- Token validation and certificate validation are transport-level checks; they do not replace application authorization.
- A missing or invalid `Authorization` metadata value returns `UNAUTHENTICATED` or `PERMISSION_DENIED` without reaching the service.
- A missing TLS peer certificate returns `UNAUTHENTICATED`; a present certificate allows the call to proceed but the caller identity must still be checked against the service's authorization model.
- gRPC status codes are machine-readable and should not leak stack traces or internal paths.

## Spring Security mapping

| Concept | gRPC / Spring API |
|---|---|
| Per-call token | `Metadata` `Authorization` ASCII string |
| Interceptor | `io.grpc.ServerInterceptor` |
| Transport identity | `Grpc.TRANSPORT_ATTR_SSL_SESSION` and `SSLSession.getPeerCertificates()` |
| Unit testing | Mockito `ServerCall`, `ServerCallHandler`, `SSLSession`, and `X509Certificate` |

## Failure and attack patterns

- **Plaintext gRPC** lets attackers intercept or replay calls.
- **Token in payload** instead of `Metadata` makes the token hard to strip at the edge.
- **Trusting CN alone** without checking the issuer or certificate chain allows spoofed certs.
- **Missing metadata interceptor** lets unauthenticated calls reach service handlers.
- **gRPC status leak** exposes internal exception details to clients.

## Guarantees and limitations

- `GrpcAuthInterceptor` validates a `Bearer` token from `Metadata` and rejects bad tokens.
- `GrpcMtlsInterceptor` extracts the peer `X509Certificate`, parses the `CN`, and rejects calls with no cert.
- The lab uses direct interceptor unit tests. Production should wire the interceptors into a `NettyServerBuilder` with real TLS and token-issuing IdP integration.
