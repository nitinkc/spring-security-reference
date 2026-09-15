# Service Identity and mTLS

Mutual TLS (mTLS) is one of the few authentication methods that binds identity directly to the network layer. A client proves its identity by presenting an X.509 certificate during the TLS handshake; the server validates it against a trusted certificate authority. There is no token, password, or browser cookie to steal.

## Security objective

Replace shared secrets between services with cryptographically bound machine identities. Every workload presents its own certificate, and the recipient can decide whether that certificate is trusted, active, and authorized.

## Core concepts

| Term | Meaning |
|---|---|
| **mTLS** | A TLS handshake in which both client and server present and verify certificates. |
| **Service identity** | The certificate subject or a stable attribute such as `CN`, `O`, or a SPIFFE URI that identifies a workload. |
| **Trust anchor** | The root CA certificate that signs the client certificates; the server trusts only clients whose chains resolve to this anchor. |
| **Subject principal** | The value extracted from the certificate that is used as the caller's principal name. |
| **X509AuthenticationFilter** | Spring Security's filter that converts a verified client certificate into an `Authentication` object. |

## Trust boundaries

- The reverse proxy or ingress must terminate TLS and request the client certificate before the request reaches the application.
- The Java container receives the certificate through the `jakarta.servlet.request.X509Certificate` request attribute.
- Spring Security's `X509AuthenticationFilter` converts that certificate into an `Authentication`.
- A `UserDetailsService` maps the extracted common name to granted authorities.
- The resulting `Authentication` is then checked by the `AuthorizationManager` for the specific route.

## Spring Security mapping

| Concept | Spring Security API |
|---|---|
| Extract principal from certificate | `x509.subjectPrincipalRegex("CN=(.*?)(?:,|$)")` |
| Map principal to authorities | `UserDetailsService` or `PreAuthenticatedGrantedAuthoritiesUserDetailsService` |
| Disable CSRF for certificate-only stateless chain | `AbstractHttpConfigurer::disable` |
| Match certificate-backed routes | `HttpSecurity#securityMatcher("/mtls/**")` |

## Failure and attack patterns

- **Missing client certificate validation** accepts any certificate, not just chains from a trusted CA.
- **Weak subject regex** can be abused by certificates with attacker-controlled `CN` values.
- **Certificate not requested** by the TLS listener means no client certificate is available to the filter.
- **Stolen key without revocation** lets an attacker reuse a certificate until expiry or CRL/OCSP action.
- **CN spoofing through RDN ordering** can trick simple regex extraction if the subject contains multiple `CN` entries or embedded commas.

## Guarantees and limitations

- This lab uses `MockMvc` and a request attribute to simulate the container-provided certificate, so it does not require a real TLS listener.
- The `X509AuthenticationFilter` extracts `CN=mtls-user` and `CN=mtls-admin`; the chain then maps those names to `ROLE_USER` and `ROLE_ADMIN`.
- `/mtls/user` accepts either role; `/mtls/admin` requires `ROLE_ADMIN`; a missing certificate is rejected.
- Real mTLS at ingress still needs a CA, certificate provisioning, rotation, revocation, and listener configuration outside the application.
