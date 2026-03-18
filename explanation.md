# Task 2.1 — System Stability Explanation

## How This Architecture Achieves System Stability

This reactive remediation system achieves system stability through three
interlocking mechanisms: fast detection, deterministic correction, and
persistent visibility.

### Fast Detection via EventBridge (~60 seconds)

EventBridge captures every `AuthorizeSecurityGroupIngress` API call from
CloudTrail within approximately 60 seconds of the modification occurring. This
near-real-time detection window is fast enough to prevent long-lived
unauthorized access rules from persisting in the environment. A Lambda
invocation adds under one second of additional latency. The combined detection
and remediation cycle completes in approximately 90 seconds from the moment a
non-compliant rule is added.

The event pattern is scoped precisely to the API call that introduces new rules
— it does not trigger on read-only describe calls, ensuring the system runs
only when genuinely needed and does not generate false-positive alerts from
normal operations.

### Deterministic Correction

The remediation logic is intentionally simple and deterministic: any ingress
rule containing a CIDR not in the approved allow-list is immediately revoked.
There is no escalation path, discretion window, or human approval step in the
automated layer. The rule is removed, period.

This determinism prevents partial compliance states where a non-compliant rule
exists temporarily while waiting for human review. The security group always
converges back to its known-good state regardless of who made the change or
why. The Lambda function handles both IPv4 and IPv6 addresses, including the
`::/0` universal IPv6 range which is treated as equivalent to `0.0.0.0/0`.

When remediation itself fails (for example, if the SG rule was already deleted
by another process), the system records the failure and triggers an elevated
alert requiring manual action — it does not silently ignore the problem.

### Persistent Visibility via DynamoDB Audit Trail

Every event — compliant changes, non-compliant changes, successful remediations,
and failed remediations — is written to the DynamoDB audit table with the actor
ARN, source IP, timestamp, affected security group ID, the specific violation
details, and the action taken.

This creates an immutable, queryable log satisfying SOC 2 CC7.2 (system
monitoring) and CC7.3 (incident response) evidence requirements. Security teams
can answer the auditor question "show me every unauthorized SG modification in
the last 90 days, who made it, and how quickly it was reverted" with a
deterministic DynamoDB query — not a manual investigation.

The three mechanisms together ensure the security group configuration is
always converging toward the compliant state, with complete audit evidence,
regardless of the volume or frequency of attempted unauthorized modifications.

