# LAB-017: SAML Relying Party

## Status

- Theory prerequisite: `docs/theory/saml-relying-party.md`
- Implementation: `saml-auth` module
- Tests: `SamlRelyingPartyLabTest`
- Verification: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :saml-auth:test`

## Measurable objective

Configure a SAML relying party with a local, self-signed SP key pair and a static IdP metadata file. Verify that the Spring Security `saml2Login()` chain:

- Loads the IdP metadata.
- Registers signing and decryption credentials for the SP.
- Redirects unauthenticated requests to the local SAML entry point.
- Allows a designated public route without authentication.

## Source artifact map

| File | Purpose |
|---|---|
| `saml-auth/build.gradle` | Module dependencies, including `spring-security-saml2-service-provider` |
| `saml-auth/src/main/resources/saml/idp-metadata.xml` | Static IdP metadata used to build the relying party |
| `saml-auth/src/main/resources/saml/sp-cert.der` | SP public certificate |
| `saml-auth/src/main/resources/saml/sp-key.der` | SP PKCS#8 private key |
| `saml-auth/src/main/java/.../samlauth/SamlAuthConfig.java` | `RelyingPartyRegistrationRepository` and `saml2Login()` filter chain |
| `saml-auth/src/main/java/.../samlauth/SamlPublicController.java` | Public and protected example routes |
| `saml-auth/src/test/java/.../samlauth/SamlRelyingPartyLabTest.java` | Executable verifications |

## Exercises

1. Inspect `saml-auth/src/main/resources/saml/idp-metadata.xml` and confirm the entity ID and single sign-on service location.
2. Review `SamlAuthConfig` and trace how `Saml2X509Credential` is constructed with `SIGNING` and `DECRYPTION` types.
3. Run the tests and confirm four assertions pass.
4. Identify why `getAssertingPartyDetails()` is marked as deprecated in Spring Security 6.5 and what replacement API would be used for `wantAuthnRequestsSigned` in a future release.

## Commands

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :saml-auth:test
```

## Positive and negative test expectations

| Scenario | Expected |
|---|---|
| `GET /saml/public` | 200 with body `SAML reference application` |
| `GET /saml/welcome` unauthenticated | 302 redirect to `**/saml2/authenticate?registrationId=lab-idp` |
| Registration `lab-idp` loaded | `entityId` equals `local:test:idp` and SSO location equals the metadata value |
| SP credentials loaded | signing and decryption credentials both contain the local certificate with `spring-security-reference-sp` subject |

## Production extension

- Replace the static metadata file with a metadata resolver that refreshes from a trusted URL or filesystem path on a schedule.
- Store SP private keys in an HSM, KMS, or secrets manager; never load them from `resources` in production.
- Add a real IdP and complete an end-to-end `SAMLResponse` flow with `POST` binding, audience, and `InResponseTo` validation.
- Map SAML attributes to local authorities through a `GrantedAuthoritiesMapper`.

## Completion evidence

```text
./gradlew :saml-auth:test
BUILD SUCCESSFUL
4 tests passed
```

## Next lab

LAB-018 — OIDC SSO with `oauth2Login()` against the local identity provider.
