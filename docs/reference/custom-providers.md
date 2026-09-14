# Custom Authentication Providers Reference

Use a custom `AuthenticationProvider` only when standard Spring Security support cannot represent the credential exchange.

## Contract

A provider should:

1. Return `false` from `supports` for authentication types it does not own.
2. Validate credentials through a dedicated service.
3. Return a new authenticated token without retaining raw credentials.
4. Throw a generic `AuthenticationException` on failure.
5. Avoid revealing whether the username or credential was incorrect.
6. Avoid logging credentials, tokens, or sensitive identity attributes.

## Required tests

- Supported token with valid credentials succeeds.
- Invalid credentials fail without account enumeration.
- Unsupported token is ignored so another provider can evaluate it.
- Returned authorities are server-derived.
- Credentials are erased after authentication where applicable.

The current implementation is in `common-auth`. Complete LAB-002 and LAB-003 before treating it as a recommended production example. See [Custom Providers](../examples/custom-providers.md) for the exercise workflow.
