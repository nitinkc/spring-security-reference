# Advanced Patterns Reference

Advanced security work in this repository is organized as executable labs rather than disconnected snippets.

## Pattern selection

| Need | Preferred pattern | Labs |
|---|---|---|
| Browser login | OIDC Authorization Code with PKCE | LAB-011, LAB-012 |
| Browser application without exposed tokens | Backend for Frontend | LAB-024 |
| API bearer authentication | OAuth2 resource server | LAB-009 |
| Workload authentication | Client Credentials or workload identity | LAB-021, LAB-025 |
| User delegation | Token relay or token exchange | LAB-022, LAB-023 |
| Enterprise federation | OIDC SSO or SAML relying party | LAB-016 through LAB-020 |
| Fine-grained data access | Method, tenant, and object authorization | LAB-004, LAB-027 |

## Design rules

- Authenticate at the boundary and authorize at every resource-owning service.
- Validate issuer, audience, signature, algorithm, and time constraints for tokens.
- Prefer short-lived credentials and documented rotation.
- Do not trust forwarded identity headers from untrusted callers.
- Keep browser tokens out of JavaScript when a BFF is appropriate.
- Define fail-open or fail-closed behavior for every identity dependency.

See the [Lab Roadmap](../labs.md) for implementation and attack-case requirements.
