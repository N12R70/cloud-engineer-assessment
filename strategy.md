
## How the Preventive SCP Architecture Aligns with Infrastructure Strategy

### The Core Principle: Guardrails That Scale Automatically

The SCP architecture described in Task 2.2 is designed around a single
principle: security controls that are configured once at the organizational
level and apply automatically to every account, present and future. This
is the right model for any organization on a high-growth trajectory.

At 10 accounts, manually auditing security configurations is feasible.
At 100 accounts — roughly the scale a Series A company reaches within two
years of hiring aggressively — it becomes impossible without automation.
The SCP hierarchy (root → OU → account) means that a new account provisioned
at 2AM inherits every relevant security control before a single engineer logs
in. There is no gap between provisioning and compliance.

This is the definition of infrastructure strategy: making decisions today
that remain correct at 10x the current scale without requiring 10x the
engineering effort.

---

### Alignment with Each SCP to Long-Term Scale

**SCP 1 — DenyPublicIngressRules (absolute guardrail)**

This policy requires no maintenance as the organization grows. A policy
that blocks `0.0.0.0/0` today blocks it in the 500th account with zero
additional configuration. It is the highest-leverage security control
available: a single JSON document prevents an entire class of security
incidents organization-wide.

At 50 accounts, this SCP replaces the equivalent of 50 manual configuration
reviews, 50 sets of AWS Config rules requiring per-account deployment, and
50 audit findings that would otherwise appear in every SOC 2 assessment.

**SCP 2 — RequireApprovedRole (production change governance)**

The approved-role model is how production engineering governance scales.
Rather than maintaining a list of engineers allowed to modify production
security groups — a list that is constantly changing as the team grows —
the system inverts the model: nobody has direct access, and legitimate
changes flow through a named, auditable role.

When engineering headcount grows from 15 to 150, this policy requires no
updates. The approval workflow (ticket → review → role assumption) scales
through process and tooling, not through policy modifications. The SCP
itself is stable.

**SCP 3 — RequireMFAForSG (compliance baseline)**

MFA enforcement for privileged operations is a baseline requirement for
SOC 2, ISO 27001, and most regulatory frameworks. Implementing it as an SCP
converts a per-engineer configuration requirement into a technical control
that cannot be bypassed.

As the organization hires engineers faster than security can onboard them
individually, this policy ensures every new hire starts compliant on day one,
regardless of whether they configure MFA themselves.

**SCP 4 — ProtectAuditInfrastructure (trust foundation)**

Audit infrastructure — CloudTrail, Config, GuardDuty — is the foundation
that all other security controls rely on. A CloudTrail gap means an audit
period cannot be defended. At 10 accounts, a single misconfiguration might
be caught in a manual review. At 50 accounts, it might not be discovered
until an auditor asks for evidence that does not exist.

Applying this SCP at the root ensures the audit foundation is inviolable
across every account at every stage of growth.

---

### Supporting 50+ Account Scale

The approved-role model (`sg-change-approved`) combined with AWS CloudFormation
StackSets is the operational deployment pattern for this architecture at scale:

1. The SCP policies are maintained in a central Terraform root module in the
   management account — one source of truth.

2. The `sg-change-approved` IAM role is deployed to all target accounts via
   a CloudFormation StackSet (or Terraform with `for_each` over account IDs),
   ensuring the role exists before the SCP takes effect.

3. When a new account is added to the Production OU, the SCP takes effect
   immediately and the StackSet automatically deploys the approved role to
   the new account within minutes.

This pattern adds zero marginal operational cost per new account. The 50th
account and the 500th account are handled identically by the same automation.

---

### The Approved Workflow as an Engineering Multiplier

The change workflow enabled by this architecture — file ticket, get approval,
assume approved role, apply change — may seem slower than direct console
access. At a team of five engineers, it is. At a team of 50 engineers across
10 production accounts, it is the only model that maintains security without
becoming a bottleneck.

The key insight is that the workflow is implemented once and reused at any
scale. A ServiceNow or Jira workflow template for security group changes,
connected to a Slack approval bot and the `sg-change-approved` role, processes
50 tickets per week with the same engineering overhead as five tickets per week.

The policy does not need to change when the workflow volume changes. This
is what infrastructure strategy means in practice: decisions that remain
correct as the organization grows, because the complexity scales in the
workflow layer (tooling), not in the infrastructure layer (policies).

---

### Measurable Outcomes at 10x Growth

| Metric | Current State | At 10x with SCP Architecture |
|--------|--------------|------------------------------|
| Time to enforce security policy on new account | Hours (manual) | Minutes (automatic) |
| SOC 2 evidence for MFA on privileged changes | Manual review | Automated CloudTrail query |
| Security group audit coverage | Per-account review | 100% via SCP + Config |
| Unauthorized 0.0.0.0/0 rules in production | Possible | Technically impossible |
| Engineer-hours per quarterly security review | 40+ hours | < 4 hours (automated reports) |

---

