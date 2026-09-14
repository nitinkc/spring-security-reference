# Repository Guide

## Purpose

This repository teaches production-oriented Spring Security and microservice security through code-backed documentation and executable labs.

## Ground rules

- Treat source code and executable tests as the ground truth.
- Do not describe a mechanism as implemented unless its runnable code and tests exist.
- Give each topic one status: Planned, Theory, Implemented, Verified, or Operational.
- Keep secrets, private keys, real credentials, tokens, and personal data out of source and logs.
- Prefer Spring Security's standard support over custom security infrastructure.
- Keep intentionally vulnerable behavior isolated, labeled, and disabled by default.
- Never weaken dependency, CI, or security controls to make a lab pass.

## Build and verification

- Java 21 and Gradle are the canonical application stack; use `./gradlew`.
- Run `./gradlew test` after Java or Gradle changes.
- Run `./gradlew :rest-api:test` for REST security labs.
- Run `uv run --with-requirements requirements.txt mkdocs build --strict` after documentation or navigation changes.
- Gradle is the only supported Java build system.

## Documentation contract

Every mechanism follows `docs/learning-model.md` with separate artifacts:

1. `docs/theory/`: protocol, threat model, Spring API mapping, failure modes, and brief transfer notes
2. `docs/tutorials/`: runnable Java 21 exercises, artifact map, positive/negative tests, evidence, and next lab
3. `docs/quizzes/`: senior scenarios and explanations

Do not duplicate full theory in a lab guide or put setup walkthroughs in theory pages.

Documentation must link to the implementing module and its lab. Code changes that alter observable security behavior must update the corresponding documentation in the same change.

## Lab contract

Each lab must state prerequisites, objective, threat model, steps, expected result, failure cases, and cleanup. Tests must cover anonymous access, valid authentication, insufficient authority, malformed or expired credentials where relevant, and the mechanism-specific attack case.

## Learning order

Follow `docs/learning-path.md` for outcomes and `docs/labs.md` for the ordered 58-lab session backlog. Start with the first incomplete lab unless the user names another lab.

## Session protocol

- Work on one lab per session unless the user explicitly broadens the scope.
- At the start, state the lab ID, current status, acceptance criteria, and verification commands.
- Preserve a failing security test before changing behavior whenever practical.
- Read `docs/progress.md` before choosing work; it is the single canonical resume point.
- At the end, update `docs/coverage.md` and the lab's documentation only when evidence supports the new status.
- Advance `docs/progress.md` only after focused tests, the full suite, and strict docs validation pass; do not create another progress list.
- Update theory first when a concept changes, then implementation/tests, then the lab evidence and quiz.
- Keep senior quiz scenarios aligned with changed security behavior; explanations must cover why distractors fail.
- Report implementation, tests, commands, proved behavior, limitations, and the next lab using the handoff template in `docs/labs.md`.
- Never skip an incomplete prerequisite silently; state why work is proceeding out of order.

## Security review checklist

For each change, check authentication bypass, authorization at object and method level, CSRF/CORS/session implications, token issuer/audience/time validation, secret exposure, secure logging, tenant isolation, replay behavior, key rotation, failure mode, and test coverage.
