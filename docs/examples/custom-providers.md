# Custom Authentication Provider Exercise

The `common-auth` module contains the provider used by this exercise.

## Objective

Understand provider selection, credential validation, authority creation, and safe authentication failure behavior.

## Procedure

1. Read `CustomAuthenticationProvider` and identify its supported token type.
2. Write a failing test for valid credentials.
3. Add tests for invalid credentials and an unsupported token type.
4. Verify authorities come from trusted server-side data.
5. Verify failure responses do not distinguish unknown users from incorrect passwords.
6. Run `./gradlew :common-auth:test` and then `./gradlew test`.

## Completion criteria

The provider authenticates only its supported token, retains no raw credential after success, logs no sensitive data, and has positive and negative tests.

This exercise is completed through LAB-002 and LAB-003. See the [Custom Providers Reference](../reference/custom-providers.md).
