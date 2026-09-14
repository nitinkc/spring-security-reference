# Deployment Overview

Deployment is part of the security boundary. A mechanism is Operational only when credential injection, rotation, observability, dependency failure, and recovery are documented and tested.

## Current state

The repository is suitable for local learning but does not yet provide a production deployment. Do not expose the demo application publicly: it contains intentionally incomplete authentication behavior and verbose educational logging.

## Progression

1. Use configuration profiles without embedding secrets.
2. Complete token, session, and authorization labs.
3. Add container hardening in LAB-043.
4. Add Kubernetes identity, networking, and secret controls in LAB-044.
5. Validate audit and incident procedures in LAB-041 through LAB-046.

See [Configuration Profiles](profiles.md) and [Production Deployment](production.md).
