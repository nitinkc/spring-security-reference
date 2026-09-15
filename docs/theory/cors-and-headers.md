# CORS and Security Headers

## Security objective

CORS decides whether browser-executed JavaScript from another origin may issue certain requests and read responses. Security headers instruct the browser to restrict framing, sniffing, referrer leakage, and script sources.

Neither mechanism is authorization. A non-browser client can ignore both.

## CORS model

| Responsibility | Spring API |
|---|---|
| Chain-level CORS | `http.cors(...)` |
| Policy source | `CorsConfigurationSource`, `UrlBasedCorsConfigurationSource` |
| Policy values | `CorsConfiguration` allowed origins, methods, headers |
| Credentialed requests | `setAllowCredentials(true)` with explicit origins |

A credentialed response must name an exact origin; wildcard origins are invalid with credentials. Allowed origins are an integrity boundary for browser scripts, not a statement of user trust.

## Header model

| Header | Spring API | Purpose |
|---|---|---|
| `Content-Security-Policy` | `headers().contentSecurityPolicy(...)` | Restrict script and framing sources |
| `X-Frame-Options` | `headers().frameOptions(...)` | Legacy clickjacking defense |
| `X-Content-Type-Options` | Default `nosniff` | Prevent MIME sniffing |
| `Referrer-Policy` | `headers().referrerPolicy(...)` | Limit URL leakage |
| `Strict-Transport-Security` | `headers().httpStrictTransportSecurity(...)` | Force HTTPS on secure origins |
| Cache directives | Default no-store behavior | Avoid caching authenticated responses |

## Trust and failure cases

- Wildcard origin with credentials
- Reflecting the request `Origin` header as allowed
- Treating an allowed origin as an authenticated identity
- Relying on CORS instead of CSRF tokens
- Missing CSP or an unsafe inline policy
- Authenticated responses cached by intermediaries

## Transfer

Browsers enforce these controls identically regardless of server framework. Spring's chain-scoped CORS source and headers DSL are framework-specific.

Continue with [LAB-008](../tutorials/lab-008-cors-and-headers.md).
