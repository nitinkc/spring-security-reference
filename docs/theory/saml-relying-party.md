# SAML Relying Party

SAML lets an application act as a **relying party (RP)** that delegates authentication to an external **identity provider (IdP)**. This page covers the trust and message-level security concepts; the lab provides the Spring Security wiring.

## Security objective

Allow a user authenticated by an enterprise IdP to access protected application routes without the application seeing the user's password. The application must:

- Trust only one or more configured IdPs.
- Verify signed `SAMLResponse` assertions.
- Keep private keys used to decrypt assertions confidential.
- Protect against replay, session fixation, and man-in-the-middle relay attacks.

## Core entities

| Term | Meaning |
|---|---|
| **Identity Provider (IdP)** | System that authenticates the user and issues a SAML assertion. |
| **Service Provider (SP)** | The application that consumes the assertion (also called a relying party). |
| **Assertion** | Signed XML statement containing the authenticated subject and attributes. |
| **AuthnRequest** | XML request the SP sends to the IdP to initiate SSO. |
| **Metadata** | XML document describing an entity's endpoints, certificates, and bindings. |
| **Entity ID** | A URI that uniquely identifies the IdP or SP in the federation. |

## Trust boundaries

- The IdP owns the user's password, MFA, and session.
- The SP owns:
  - Its own certificate and private key.
  - The mapping of SAML attributes to local roles.
  - The application session that is created after a validated assertion.
- Metadata exchange is out-of-band; both parties must verify the entity ID and certificate fingerprint before federation.

## Message security

SAML security is **message-level**, not transport-level only.

- **Signed assertions** prove the assertion came from the IdP and has not been tampered with.
- **Signed AuthnRequests** prove the request came from the registered SP.
- **Encrypted assertions** prevent an attacker with access to the network from reading attributes.
- The SP must validate:
  - `Destination` matches the SP's assertion consumer service.
  - `InResponseTo` matches the original `AuthnRequest` ID.
  - `NotOnOrAfter` is in the future.
  - `Recipient` and `Audience` match the SP entity ID.

## Spring Security mapping

Spring Security's `saml2Login()` builds an `OpenSAML4` based relying party.

| Concept | Spring Security API |
|---|---|
| IdP metadata | `RelyingPartyRegistrations.fromMetadata(...)` or `fromMetadataLocation(...)` |
| SP registration repository | `RelyingPartyRegistrationRepository` / `InMemoryRelyingPartyRegistrationRepository` |
| SP signing and decryption | `Saml2X509Credential` with `SIGNING` and `DECRYPTION` types |
| SSO entry point | `Saml2WebSsoAuthenticationRequestFilter` and `Saml2WebSsoAuthenticationFilter` |
| Filter chain | `HttpSecurity#saml2Login(...)` and `HttpSecurity#securityMatcher(...)` |

## Failure and attack patterns

- **No signature validation** lets an attacker replay a valid assertion for a different user.
- **No audience check** lets an assertion issued for `sp-2` be used at `sp-1`.
- **Weak or reused keys** let an attacker sign fake requests or decrypt assertions.
- **No `InResponseTo` check** enables replay of old responses.
- **Metadata spoofing** if metadata is fetched over HTTP without verification.

## Guarantees and limitations

- Spring Security verifies the XML signature, audience, recipient, and `NotOnOrAfter` by default.
- It does **not** validate all certificate path properties by default; a real deployment may need an explicit trust anchor.
- The configuration in this lab uses a local self-signed certificate and a static metadata file. It is a learning artifact, not a production IdP trust relationship.
