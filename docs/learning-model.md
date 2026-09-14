# Theory and Lab Learning Model

Java 21 and Spring Boot are the canonical implementation stack. Theory and hands-on work are separate artifacts so learners can study concepts without searching through exercise instructions.

## Theory pages

Theory lives under `docs/theory/` or the relevant Security reference section. A theory page contains:

1. Protocol or security objective
2. Assets, actors, and trust boundaries
3. Guarantees and non-guarantees
4. Concrete Spring Security API mapping
5. Failure modes and attack patterns
6. Brief cross-framework transfer notes
7. Link to the corresponding lab

Theory pages contain no setup walkthrough and never claim runnable evidence.

## Lab guides

Labs live under `docs/tutorials/`. A lab guide contains:

1. Status and theory prerequisite
2. Measurable objective
3. Source artifact map
4. Step-by-step exercises
5. Positive and negative tests
6. Verification commands
7. Completion evidence
8. Production extension and next lab

Source code and executable tests—not snippets—are canonical.

## Assessments

Senior assessments live under `docs/quizzes/`. Questions test ambiguous production scenarios, Spring internals, protocol boundaries, attacks, and failure policy. Explanations must state why distractors are unsafe or incomplete.

## Status gates

- **Planned:** scope exists but no complete theory or code.
- **Theory:** conceptual page exists, but no runnable Spring implementation.
- **Implemented:** production code runs through the intended Spring boundary.
- **Verified:** positive and negative automated tests pass.
- **Operational:** deployment, rotation, observability, outage, and recovery behavior are tested.

## Session order

1. Read or correct the theory page.
2. Write a failing lab test.
3. Implement the smallest production change.
4. Run focused and full tests.
5. Update the lab guide and evidence status.
6. Update senior assessment questions when behavior changes.
7. Select the next incomplete lab.

The [Theory Index](theory/index.md), [Lab Roadmap](labs.md), [Tutorials](tutorials/lab-001-request-authorization.md), and [Senior Assessments](quizzes/index.md) are independent navigation paths.
