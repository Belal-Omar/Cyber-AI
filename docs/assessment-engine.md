# Assessment Engine

The Assessment Engine is a modular subsystem designed to run structured security checks against authorized targets. It translates network/system interactions into raw observations.

## Modular Check Interface
Every security check implements a standard interface (e.g., `AssessmentCheck`).

### Interface Methods
- `metadata()`: Returns check details (name, category, severity hint, required scope).
- `can_run(context)`: Evaluates if the check is applicable (e.g., is the target within scope? is it an HTTP endpoint?).
- `run(context)`: Executes the interaction safely against the target.
- `produce_observation()`: Returns a raw `Observation` object containing the technical output.
- `verify(original_context)`: Re-runs the check using parameters from a past finding to verify remediation.

## Observations vs. Findings
- **Observation**: Raw, atomic output from a check (e.g., "HTTP response is missing X-Frame-Options header").
- **Finding**: A structured security issue derived by the backend after deduplicating and analyzing one or more observations (e.g., "Missing Security Headers").

## Current Scope Limits
In Phase 0 and Phase 1, the engine is restricted to harmless checks (e.g., header analysis, cookie inspection) running exclusively against local applications in `/test-targets/`.
