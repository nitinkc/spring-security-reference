# LAB-021: Service Identity and mTLS

## Status

- Theory prerequisite: `docs/theory/service-identity-mtls.md`
- Implementation: `rest-api` module
- Tests: `MtlsLabTest`
- Verification: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*MtlsLabTest'`

## Measurable objective

Configure a dedicated `/mtls/**` filter chain that uses `X509AuthenticationFilter` to extract the principal from a client certificate and enforce role-based authorization. Tests must prove that a valid user certificate, a valid admin certificate, a user certificate on an admin route, and a missing certificate are handled correctly.

## Source artifact map

| File | Purpose |
|---|---|
| `MtlsAuthConfig.java` | Isolated `SecurityFilterChain` for `/mtls/**` with `x509` authentication and role rules |
| `MtlsController.java` | `/mtls/user` and `/mtls/admin` endpoints that echo the principal and authorities |
| `MtlsLabTest.java` | Loads test certificates and asserts positive/negative mTLS behavior |
| `mtls-user-cert.pem`, `mtls-admin-cert.pem` | Test X.509 certificates loaded from the test classpath |

## Exercises

1. Review `MtlsAuthConfig` and explain how `securityMatcher("/mtls/**")` keeps the certificate chain from conflicting with the other filter chains.
2. Trace how `x509.subjectPrincipalRegex` maps the certificate subject to the principal name.
3. Run `MtlsLabTest` and confirm that the user certificate cannot reach `/mtls/admin`.
4. List the production tasks that a real mTLS listener would still require beyond this Spring configuration.

## Commands

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*MtlsLabTest'
```

## Positive and negative test expectations

| Scenario | Expected |
|---|---|
| User certificate on `/mtls/user` | 200, `mTLS user: mtls-user` |
| Admin certificate on `/mtls/admin` | 200, `mTLS admin: mtls-admin [ROLE_ADMIN]` |
| User certificate on `/mtls/admin` | 403 |
| No certificate on `/mtls/user` | 4xx client error |

## Production extension

- Configure the ingress or servlet container to request and validate client certificates against a trusted CA.
- Add certificate pinning, CRL, or OCSP revocation checks.
- Replace the in-memory `UserDetailsService` with a service-identity directory that maps SPIFFE IDs or certificate fingerprints to roles.
- Use `PreAuthenticatedGrantedAuthoritiesUserDetailsService` when the certificate itself carries group or role attributes.
- Rotate certificates automatically through a workload identity provider or cert-manager.

## Completion evidence

```text
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*MtlsLabTest'
BUILD SUCCESSFUL
MtlsLabTest: 4 passed
```

## Next lab

LAB-022 — API Keys and Resource Quotas.
