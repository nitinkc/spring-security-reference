# Senior Security Assessments

These quizzes test production judgment, not terminology. Study the separate [Theory Index](../theory/index.md), complete the related labs, and then take each assessment.

## Assessment rules

- Select every defensible answer when a question allows multiple selections.
- Explain your decision before submitting; guessing the option is not mastery.
- After submission, compare your reasoning with the explanation.
- Revisit the linked labs when you cannot explain why every distractor is wrong.
- Target at least 85% twice, on different days, before considering a track understood.

## Assessments

| Assessment | Focus | Prerequisite labs |
|---|---|---|
| [Spring Security internals](fundamentals.md) | Filter chains, contexts, sessions, CSRF, authorization | LAB-001 through LAB-009 |
| [SSO and federation](federation.md) | OAuth2, OIDC, SAML, sessions, logout, federation threats | LAB-010 through LAB-020 |
| [Microservice security](microservices.md) | Delegation, gateways, mTLS, tenancy, protocols | LAB-021 through LAB-039 |
| [Operations and architecture](operations.md) | Rotation, incidents, supply chain, policy, data protection | LAB-040 through LAB-058 |

## Senior answer standard

For each scenario, be able to state:

1. The asset and trust boundary
2. Authentication evidence and who issued it
3. Where authorization must occur
4. Replay, rotation, and revocation behavior
5. Failure mode and observable evidence
6. The negative test that proves the decision
