# Senior Quiz: Spring Security Internals

<quiz>
Two `SecurityFilterChain` beans match `/api/admin/reports`. The first chain has a broader `/api/**` matcher and permits the request; the second requires ADMIN. What is the correct response?

- [ ] Spring Security merges both authorization rule sets
- [x] Only the first matching chain applies, so chain order and `securityMatcher` boundaries must be corrected
- [ ] Method security automatically repairs the HTTP configuration
- [ ] Add another JWT filter before both chains

`FilterChainProxy` selects the first matching chain; it does not merge chains. A production test must prove `/api/admin/**` cannot be captured by a broader permissive chain. Method security is defense in depth, not a reason to leave the request boundary exposed.
</quiz>

<quiz>
An authenticated USER requests an ADMIN endpoint. Which response and component responsibilities are correct?

- [ ] 401 from `AuthenticationEntryPoint`
- [x] 403 from `AccessDeniedHandler`
- [x] The response should avoid exposing internal authorization expressions
- [ ] Clear authentication and redirect every client to login

The caller has an identity, so the failure is authorization and normally maps to 403. A 401 means authentication is absent or invalid. Browser and API error behavior may differ, but neither should leak policy internals.
</quiz>

<quiz>
A team adds `@ControllerAdvice` for `AccessDeniedException`, but request authorization failures still return Spring's default response. Why?

- [x] Many security failures occur in the filter chain before controller invocation
- [x] Configure `AuthenticationEntryPoint` and `AccessDeniedHandler` for that security chain
- [ ] Add the exception message directly to every response
- [ ] Permit the endpoint so the controller advice can run

`ExceptionTranslationFilter` handles authentication and authorization failures at the security boundary. Stable API JSON belongs in the entry point and denied handler; controller advice remains useful for failures raised inside controller/business execution.
</quiz>

<quiz>
A browser SPA calls a state-changing API with an HttpOnly session cookie. The API returns JSON and has no HTML forms. Is disabling CSRF safe?

- [ ] Yes, because JSON APIs are immune to CSRF
- [ ] Yes, because the cookie is HttpOnly
- [x] No, browsers attach cookies automatically; the API needs a CSRF defense unless another robust boundary prevents cross-site requests
- [ ] No, but CORS alone always replaces CSRF protection

CSRF depends on ambient credentials, not response format. HttpOnly prevents JavaScript from reading a cookie but does not stop the browser sending it. CORS is not a universal CSRF substitute and simple requests may not preflight.
</quiz>

<quiz>
Select the statements that correctly distinguish CORS from authorization.

- [x] CORS controls whether browser JavaScript may read or issue certain cross-origin requests
- [x] Non-browser clients can ignore CORS entirely
- [x] Authorization must still protect every endpoint
- [ ] An allowed origin proves the requesting user is trusted

Origins are browser execution boundaries, not identities. Never convert an origin allow list into a user or workload authorization decision.
</quiz>

<quiz>
A browser application keeps the same session identifier before and after login. Why is this dangerous, and what fixes it?

- [x] An identifier known to an attacker before login stays valid afterwards
- [x] Rotate the session identifier during authentication, for example with `changeSessionId`
- [x] Invalidate server-side session state at logout rather than only deleting the cookie
- [ ] Set the session cookie to `HttpOnly` and keep the same identifier

Session fixation lets an attacker pre-seed an identifier and inherit the authenticated session. `HttpOnly` prevents script access but does not rotate or invalidate anything.
</quiz>

<quiz>
One application has a cookie-authenticated browser chain and a bearer-token API chain. How should CSRF and session policy be configured?

- [x] Enable CSRF and use a session policy that permits sessions on the browser chain
- [x] Keep the API chain stateless with an explicit bearer credential
- [x] Separate the two into different `SecurityFilterChain` beans with distinct matchers
- [ ] Disable CSRF globally so the API chain does not need a token

CSRF depends on ambient credentials, so protection follows the authentication style rather than the whole application. Chain-scoped configuration avoids weakening one flow to satisfy the other.
</quiz>

<quiz>
A credentialed CORS response is configured with `Access-Control-Allow-Origin: *` and the browser refuses it. What is the correct fix?

- [x] Return the exact approved origin instead of a wildcard
- [x] Keep the origin list in server-controlled configuration
- [ ] Reflect whatever `Origin` header the request supplied
- [ ] Remove `allowCredentials` and rely on CORS for CSRF protection

Wildcards are invalid with credentials, and reflecting the request origin defeats the boundary entirely. CORS also never replaces a CSRF token for cookie-authenticated state changes.
</quiz>

<quiz>
A service method has `@PreAuthorize`, but direct calls from another method in the same class are not intercepted. What is the likely cause?

- [x] Self-invocation bypasses the Spring proxy that applies method security
- [ ] The JWT lacks a CSRF claim
- [ ] `hasRole` works only in controllers
- [ ] The method must return `Authentication`

Proxy-based method security requires invocation through the proxied bean. Refactor the protected operation to a separate bean or use an appropriate interception strategy, then test calls through the real boundary.
</quiz>

<quiz>
Which controls are required when migrating stored passwords from an older encoder?

- [x] Store an encoding identifier or use `DelegatingPasswordEncoder`
- [x] Re-encode after successful verification when an upgrade is needed
- [x] Avoid logging plaintext or hashes
- [ ] Decrypt the old password and encrypt it with BCrypt

Password hashes should not be decryptable. Migration normally verifies with the old encoder, then hashes the supplied password with the current encoder after successful authentication.
</quiz>

<quiz>
A custom JWT filter catches every parsing exception, logs the exception message, and continues anonymously. What can go wrong?

- [x] Protected endpoints may still deny access, but clients receive misleading behavior instead of a clear invalid-credential response
- [x] Parser messages or token content may leak into logs
- [x] Multiple authentication mechanisms may behave ambiguously
- [ ] Continuing anonymously guarantees a 401 for every route

Invalid presented credentials should have an intentional failure path. Public routes may continue, but protected routes need a stable error contract, safe diagnostics, and unambiguous filter ownership.
</quiz>

<quiz>
An ADMIN role is stored as `ADMIN`, while a rule uses `hasRole("ADMIN")`. Which authority must Spring normally see?

- [ ] `ADMIN`
- [x] `ROLE_ADMIN`
- [ ] `SCOPE_ADMIN`
- [ ] `GROUP_ADMIN`

`hasRole` normally applies the `ROLE_` prefix. Use `hasAuthority` for exact values and normalize authority mapping at one trusted boundary.
</quiz>

<quiz>
A login controller checks the submitted username to choose `ROLE_ADMIN`, generates a JWT, and never calls `AuthenticationManager`. Which changes are required?

- [x] Submit an unauthenticated token to `AuthenticationManager`
- [x] Issue the JWT only from the returned authenticated identity and trusted authorities
- [x] Return a uniform failure for unknown users and wrong passwords
- [ ] Trust a `role` request parameter after checking that it is non-empty

Token issuance must be downstream of successful authentication. Spring's manager selects the supporting provider, while authorities come from trusted server-side identity data. Uniform public failures reduce account enumeration.
</quiz>

<quiz>
A database contains `{noop}password` for legacy users and `{bcrypt}...` for current users. What is the safe migration behavior?

- [x] Verify using the encoder selected by the stored prefix
- [x] Re-encode with the current encoder only after a successful match
- [x] Update persistent storage atomically and tolerate concurrent successful logins
- [ ] Configure unprefixed values to use plaintext automatically

`DelegatingPasswordEncoder` makes the old format explicit. Silent unprefixed fallback hides corrupt or plaintext records. Migration must never occur after a failed match, and production updates need concurrency and audit handling without logging secrets.
</quiz>
