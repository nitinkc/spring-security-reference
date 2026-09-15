# API Key Lifecycle

Long-lived credentials such as API keys require lifecycle controls that ordinary session tokens do not. They are usually machine-generated, shared with integrations, and survive for days or months. Without storage, rotation, and revocation discipline, a single leak can stay exploitable for the lifetime of the key.

## Security objective

Issue, store, rotate, and revoke API keys in a way that means a database dump or log leak does not expose reusable secrets, and a stolen key can be disabled without breaking every integration.

## Core concepts

| Term | Meaning |
|---|---|
| **Prefixed key** | An API key divided into a public `prefix` (for lookup and logs) and a secret part (for validation). |
| **Hash storage** | Storing only a one-way hash plus salt of the secret, never the plain secret, so a database leak does not reveal usable credentials. |
| **Scope** | The set of permissions attached to a key, expressed as machine-readable scopes. |
| **Rotation** | Issuing a new key while allowing the old one to work for a bounded grace period, then retiring it. |
| **Revocation** | Marking a key as no longer valid immediately, regardless of expiry. |
| **Audit trail** | Records of who issued, rotated, or revoked a key and when. |

## Trust boundaries

- The full secret is shown to the caller exactly once during issuance.
- The storage layer keeps only the hash, never the full secret or a reversible value.
- The prefix is sufficient for lookup and support but is not a credential.
- A revoked or expired key must be rejected even if the hash itself has not been removed yet.
- Scope enforcement is checked on every request, not just at the gateway.

## Spring Security mapping

| Concept | Spring Security API |
|---|---|
| Stateless API-key authentication | `OncePerRequestFilter` extracting `X-API-Key` and setting `SecurityContext` |
| Scope-based authorization | `SimpleGrantedAuthority` with `SCOPE_` prefix and `hasAuthority` |
| Secure key validation | `SecureApiKeyService` separating lookup, expiry, revocation, and hash verification |
| Key metadata model | `SecureApiKey` record with salt, scopes, issued, expires, and revoked times |

## Failure and attack patterns

- **Plaintext key storage** lets an attacker who reads the database replay every key.
- **No salt** allows precomputed hash tables and rainbow attacks.
- **Single shared key** forces all integrations to be re-keyed at once when one leaks.
- **No revocation** means a leaked key remains useful until expiry.
- **Key in logs or URLs** leaks the secret outside the intended channel.
- **Confusing prefix and secret** can lead a developer to store or transmit the full secret as a non-secret lookup value.

## Guarantees and limitations

- `SecureApiKeyService` issues a full key only once; the full secret is hashed with salt and then discarded.
- Keys can be scoped to one or more `SCOPE_*` authorities, expired, revoked, or rotated with a short grace period.
- The lab uses an in-memory, unencrypted store. Production must encrypt the hashes and metadata at rest and persist them with immutable audit events.
- Keys are never logged by the lab controller, and they are accepted only in an `X-API-Key` header.
