# Verification Lifecycle

Verification (or "Recheck") is a core feature that ensures a vulnerability has been properly remediated based on deterministic technical evidence.

## Verification Workflow
1. **Trigger**: A user selects a Finding and clicks "Verify Fix".
2. **Context Retrieval**: The system fetches the original `finding_evidence`, the `endpoint`, and the exact `assessment_config` that produced the finding.
3. **Check Execution**: The system instantiates the specific `AssessmentCheck` module that originally detected the vulnerability and passes the historical context to its `verify()` method.
4. **New Evidence Generation**: The check executes and generates new technical evidence.
5. **Comparison & Result**: The engine compares the new evidence with the expected baseline for remediation.
6. **Status Update**: A new `verification_run` record is created. The Finding status is updated based on the result:
   - `FIXED`: The vulnerability is demonstrably absent.
   - `STILL_PRESENT`: The technical evidence matches the vulnerable state.
   - `INCONCLUSIVE`: The check failed to run (e.g., endpoint no longer exists, network error).

This approach ensures findings are not blindly closed just because an endpoint returns HTTP 200; they are verified using the exact vulnerability-specific detection logic.
