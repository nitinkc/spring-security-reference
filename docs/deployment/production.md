# Production Deployment

The current repository is a learning system, not a production-ready service. Use this checklist to understand the remaining operational work.

## Required controls

- Replace demo login and custom bearer-token behavior with verified standard mechanisms.
- Load credentials and keys from an external secret source and test rotation.
- Terminate TLS deliberately and use mTLS or workload identity where required.
- Disable development consoles and restrict management endpoints.
- Use privacy-safe logging and structured security audit events.
- Define issuer/JWK/introspection outage behavior.
- Run as a non-root identity with minimum filesystem and network access.
- Add dependency, image, and configuration scanning in CI.
- Define backup, recovery, revocation, and incident procedures.

## Release gate

A release candidate should pass:

```bash
./gradlew test
uv run --with-requirements requirements.txt mkdocs build --strict
```

It must also complete the relevant Operational labs in the [Lab Roadmap](../labs.md), especially LAB-040 through LAB-046. The `prod` profile alone is not a production certification.
