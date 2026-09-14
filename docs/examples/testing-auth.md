# Testing Authentication

Use one test for every important allow rule and at least one test for every denial boundary.

## Current lab

`RequestAuthorizationLabTest` demonstrates a public endpoint, anonymous rejection, USER access, USER-to-ADMIN denial, and ADMIN access. It currently uses a test security chain.

LAB-001 now loads the production chain so configuration drift becomes visible. LAB-002 uses the production `AuthenticationManager` and provider to prove credentials are validated before token issuance.

## Workflow

1. Write the expected denial test first.
2. Run the focused test and confirm it fails for the expected reason.
3. Implement the smallest security change.
4. Run the focused module and full repository tests.
5. Update the coverage status only after both allow and deny cases pass.

```bash
./gradlew :rest-api:test --tests '*RequestAuthorizationLabTest'
./gradlew test
```

See the [Authentication Testing Reference](../reference/testing-auth.md) for the full test matrix.
