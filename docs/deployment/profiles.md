# Configuration Profiles

Profiles select learning scenarios; they must not become a substitute for authorization or secret management.

| Profile | Intended use |
|---|---|
| default/dev | Local multi-mechanism exploration |
| jdbc-only | JDBC authentication exercises |
| ldap-only | Embedded LDAP exercises |
| oauth2-only | OAuth2/OIDC exercises after local IdP configuration |
| prod | Reserved for hardened settings; not production-ready today |

## Usage

```bash
./gradlew :rest-api:bootRun --args='--spring.profiles.active=jdbc-only'
```

## Rules

- Keep real client secrets and signing keys outside profile files.
- Fail startup when required production configuration is absent.
- Do not use a profile to bypass authentication or tests.
- Test each security-sensitive profile's active `SecurityFilterChain`.
- Document profile-specific ports, dependencies, and trust boundaries.

The current `prod` profile changes logging and port settings only; it does not make the application production-ready.
