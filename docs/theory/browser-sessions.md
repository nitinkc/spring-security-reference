# Browser Sessions and Session Fixation

## Security objective

A browser client authenticates once and then carries a session cookie. The session identifier becomes a bearer credential, so its lifecycle must be controlled as carefully as a password.

## Session lifecycle

1. An anonymous request may create a session for state such as a saved request.
2. Authentication succeeds.
3. The container issues a **new** session identifier and copies approved attributes.
4. The authenticated session is used for subsequent requests.
5. Logout invalidates the session and clears the cookie.

Step 3 is session-fixation protection. Without it, an identifier known to an attacker before login remains valid afterwards.

## Spring Security model

| Responsibility | Spring API |
|---|---|
| Session creation policy | `sessionManagement().sessionCreationPolicy(...)` |
| Fixation protection | `sessionFixation().changeSessionId()` |
| Authentication session strategy | `SessionFixationProtectionStrategy` |
| Form login | `formLogin()` |
| Logout and cookie removal | `logout().invalidateHttpSession(true).deleteCookies("JSESSIONID")` |
| Concurrency limits | `maximumSessions`, `maxSessionsPreventsLogin` |

`SessionCreationPolicy.STATELESS` is correct for bearer-token APIs and wrong for cookie-based browser flows. Separate chains should own separate policies.

## Cookie attributes

A session cookie should be `HttpOnly`, `Secure` in any non-local environment, and use an appropriate `SameSite` value. `HttpOnly` blocks JavaScript access; it does not prevent the browser from sending the cookie, so CSRF defenses remain necessary.

## Trust and failure cases

- Fixation protection disabled or overridden by a custom strategy
- Logout that clears client state without invalidating the server session
- Session cookie readable by JavaScript
- Idle and absolute session lifetimes never enforced
- Privilege change during a session without re-authentication
- One chain applying stateless policy to a browser flow

## Transfer

FastAPI and Node session middleware must regenerate the identifier on privilege change and destroy server-side state on logout. Spring's chain-scoped session strategy and fixation configuration are framework-specific.

Continue with [LAB-006](../tutorials/lab-006-browser-sessions.md).
