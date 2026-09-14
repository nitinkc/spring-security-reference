# Senior Quiz: Operations and Architecture

<quiz>
A signing key is suspected compromised. Which actions belong in the response plan?

- [x] Stop or constrain issuance with the affected key
- [x] Publish/activate a trusted replacement and revoke trust in the compromised key as quickly as the risk permits
- [x] Assess issued-token lifetime, caches, sessions, and downstream verifier refresh
- [x] Preserve audit evidence and monitor for use
- [ ] Delete logs to prevent disclosure

Key response spans issuers, verifiers, caches, sessions, and long-lived connections. Routine overlap may be inappropriate during confirmed compromise.
</quiz>

<quiz>
An introspection endpoint is unavailable. Should the API accept tokens it cannot verify?

- [ ] Always, to preserve availability
- [x] Normally fail closed for new authorization decisions, with any bounded cache behavior explicitly risk-assessed
- [ ] Convert every token to anonymous and return public data
- [ ] Skip scopes until the provider returns

Availability requirements do not silently authorize unverifiable credentials. Cache lifetime, revocation exposure, criticality, and user impact must be explicit.
</quiz>

<quiz>
Which security metrics are likely to create dangerous cardinality if used as labels?

- [x] Username
- [x] Raw token identifier
- [x] Full request URL containing object IDs
- [ ] Bounded outcome such as `invalid_signature`

Attacker-controlled or near-unique labels can exhaust the monitoring system and leak sensitive data. Put bounded classifications in metrics and detailed identifiers only in protected, redacted logs when necessary.
</quiz>

<quiz>
A CI job builds untrusted pull requests and has production publishing credentials available. What is the core problem?

- [x] Untrusted code can exfiltrate or misuse privileged credentials
- [ ] Gradle cannot build pull requests
- [ ] SBOM generation automatically publishes artifacts
- [ ] Branch names are authentication tokens

Separate untrusted validation from trusted release jobs. Use short-lived workload identity, environment protections, minimal permissions, and provenance for publishing.
</quiz>

<quiz>
What does an SBOM prove?

- [ ] The application has no vulnerabilities
- [ ] Every dependency is trustworthy
- [x] It records declared or discovered components for inventory and analysis; it does not by itself prove safety or provenance
- [ ] Runtime authorization is correctly configured

Combine an SBOM with dependency verification, scanning, provenance, patch processes, and risk decisions.
</quiz>

<quiz>
An external policy engine times out while evaluating a money-transfer request. Which design questions must already be answered?

- [x] Whether this operation fails closed
- [x] Whether cached decisions are allowed and for how long
- [x] Which attributes and policy version produced the decision
- [x] How the outage is observed and recovered
- [ ] Which frontend color represents timeout

External authorization creates a runtime dependency. Critical operations need explicit failure, caching, audit, and recovery semantics.
</quiz>

<quiz>
A troubleshooting team enables full HTTP logging and captures bearer tokens, cookies, and SAML responses. What is the correct remediation?

- [x] Centralize redaction and use metadata such as issuer, key ID, bounded error class, and correlation ID
- [x] Restrict and review diagnostic access and retention
- [x] Rotate or revoke credentials that may have been exposed
- [ ] Keep the logs indefinitely because they help debugging

Credentials and assertions in logs create a secondary credential store. Diagnose validation stages without retaining reusable secrets or excessive identity attributes.
</quiz>

<quiz>
A service allows users to supply any URL for an avatar import, and the server fetches it. Which controls address the trust boundary?

- [x] Scheme and destination allow policy
- [x] DNS/IP resolution checks including redirects and private/link-local ranges
- [x] Egress restrictions, timeouts, and response-size limits
- [x] Tests for redirect and DNS-rebinding behavior
- [ ] CORS configuration on the service

Server-side fetching creates SSRF risk. Browser CORS does not constrain server egress or metadata/internal-service access.
</quiz>
