# Senior Quiz: SSO and Federation

<quiz>
A team says, “We use OAuth2, therefore user authentication and SSO are covered.” What is the best correction?

- [ ] OAuth2 and SSO are synonyms
- [x] OAuth2 delegates authorization; OIDC adds an identity and authentication layer, while SSO is the cross-application outcome
- [ ] JWT automatically adds OIDC semantics
- [ ] SAML is required for all SSO

OAuth2 access tokens authorize API access. OIDC defines ID tokens, nonce, UserInfo, authentication context, and session/logout conventions used for login. Both OIDC and SAML can produce SSO.
</quiz>

<quiz>
A user logs into Application A through an OIDC provider and then opens Application B without re-entering credentials. Which sessions normally exist?

- [x] An IdP session
- [x] A local Application A session
- [x] A separate local Application B session
- [ ] One application cookie shared by A, B, and the IdP

The IdP session enables a prompt-free response to B, but each client normally owns its local session. Sharing an application cookie across unrelated clients expands the trust and compromise boundary.
</quiz>

<quiz>
Application A deletes its local cookie and displays “You are fully signed out everywhere.” Why is this dangerous?

- [x] The IdP session may remain active
- [x] Other application sessions may remain active
- [x] The UI misrepresents local logout as global logout
- [ ] Deleting any cookie automatically triggers SAML Single Logout

Logout semantics must distinguish local, RP-initiated/provider, back-channel, SAML SLO, and global outcomes. Partial failure must be visible and documented.
</quiz>

<quiz>
Which validations belong to an OIDC authorization-code login?

- [x] Exact redirect URI and state
- [x] Nonce for ID-token response correlation
- [x] PKCE, especially for public clients
- [x] Issuer, signature, algorithm, audience, and time validation
- [ ] Trust any `iss` value and fetch its advertised JWK set

The issuer must come from trusted client configuration. Allowing a token to choose an arbitrary issuer or JWK endpoint creates SSRF and trust-confusion risks.
</quiz>

<quiz>
A SAML response has a valid signature from a trusted certificate. Which additional failures must still cause rejection?

- [x] Wrong audience
- [x] Wrong destination or recipient
- [x] Expired assertion outside bounded clock skew
- [x] Invalid request correlation or replay
- [ ] Missing application password

Signature validity proves integrity and signer possession, not that the assertion was intended for this relying party, endpoint, request, or time.
</quiz>

<quiz>
An IdP sends a user-editable `department=administrators` claim. The application maps any department directly to `ROLE_<VALUE>`. What is the right design?

- [ ] Keep the mapping because the IdP signed the token
- [x] Map only allow-listed, contractually controlled claims or groups to bounded local authorities
- [ ] Give every federated user ADMIN and authorize later
- [ ] Read authorities from a browser header instead

A signed claim is only as trustworthy as its source and governance. Authority mapping needs an explicit contract, allow list, normalization, and negative tests for unexpected values.
</quiz>

<quiz>
Should an application forward an OIDC ID token or SAML assertion to every downstream API?

- [ ] Yes, both are universal bearer credentials
- [x] No; use an audience-restricted access token or exchanged downstream credential
- [ ] Yes, if the payload contains an email address
- [ ] SAML assertions are safe after Base64 encoding

ID tokens target the client, and SAML assertions target the relying party/ACS flow. APIs require credentials intended for their audience and authorization model.
</quiz>

<quiz>
During SAML signing-certificate rollover, what is the safest operational approach?

- [x] Establish a bounded overlap where trusted old and new certificates are accepted
- [x] Validate metadata provenance and test both transition directions
- [x] Remove the old certificate after the documented cutover and observation period
- [ ] Disable signature validation during the rollover window

Rollover is a trust change, not a reason to bypass validation. Emergency replacement and metadata compromise need separate runbooks and audit evidence.
</quiz>
