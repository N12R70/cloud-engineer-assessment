# Migrating to AWS IAM Identity Center
## Technical Proposal

**Prepared for:** Chief Technology Officer  
**Company:** [Client Company]  
**Prepared by:** Cloud Engineering Team  
**Date:** 2026-03-18  
**Classification:** Confidential

---

## Executive Summary

Your current setup — individual IAM users with long-lived access keys — is one
of the most common sources of AWS security incidents and SOC 2 audit findings.
AWS IAM Identity Center eliminates this risk class entirely while simultaneously
improving your engineers' daily workflow.

Migration takes 2-3 sprints, requires zero application downtime, and directly
satisfies four SOC 2 Type II controls (CC6.1, CC6.2, CC6.3, CC6.7) that
would otherwise require manual evidence collection before every audit.

**The outcome in three numbers:**

- Zero long-lived credentials on engineer workstations after migration
- Instant access revocation when an engineer departs (down from hours or days)
- SOC 2 Type II: four manual compliance controls become one automated technical
  control

---

## The Problem with Your Current Setup

### What long-lived access keys mean in practice

Every engineer on your team has an `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` stored somewhere: their laptop, a shell profile, a
`.env` file, or — in the worst cases — a Git repository. These credentials
share four dangerous properties.

**They never expire.** An access key created during an engineer's first week
remains valid indefinitely unless someone manually rotates it. In practice,
rotation rarely happens because it requires coordinating across every system
where the key is used.

**They follow the engineer everywhere.** The same credential that accesses
production from the office also exists on the engineer's home laptop, their
personal cloud storage backup, and potentially their former employer's systems
if they switch jobs.

**They cannot be revoked instantly.** When an engineer gives notice, the
security response depends on someone remembering to disable their IAM user —
a manual process that is easy to forget, especially during busy periods.

**They are not tied to individual identity.** Two engineers with identical
permissions appear as the same IAM user ARN in CloudTrail logs. Auditors
cannot distinguish who took which action.

### What your SOC 2 auditor will ask

"Can you demonstrate that all privileged AWS access requires multi-factor
authentication?"

"Show me your access review records for the past 12 months."

"Demonstrate that access was revoked within 24 hours of this engineer's
departure date."

With IAM users and static access keys, answering these questions requires
manual processes, spreadsheet reviews, and potentially uncomfortable
conversations about gaps. With IAM Identity Center, every question has a
machine-generated, auditor-ready answer.

---

## The Solution: AWS IAM Identity Center

IAM Identity Center (formerly AWS SSO) is AWS's managed identity broker. It
connects your existing identity provider — Google Workspace, Okta, or Azure
Active Directory — to AWS access. Engineers authenticate with their corporate
credentials and receive temporary AWS credentials valid for 4-8 hours.

There are no permanent keys. There is nothing to rotate. There is nothing to
accidentally commit to a Git repository.

### Technical Comparison

| Dimension | IAM Users + Access Keys | IAM Identity Center |
|-----------|------------------------|---------------------|
| Credential lifetime | Permanent | 1-8 hours (configurable) |
| Revocation time | Minutes to hours (manual) | Instantaneous |
| MFA enforcement | Per-user, inconsistent | Enforced at IdP, centrally |
| Audit trail | User ARN in CloudTrail | Named engineer + session ID |
| Onboarding | Create user, attach policies, share key | Add to IdP group |
| Offboarding | Disable user, rotate shared keys | Remove from Okta/Google |
| Multiple AWS accounts | Separate user per account | Single login, all accounts |
| Compliance evidence | Manual credential reports | Automated access reviews |
| Developer experience | Static key on disk | Browser login, auto-renewing token |
| Cost | Free | Free |

### How it works technically

```
Engineer opens terminal
  → runs: aws sso login
  → browser opens to Google Workspace / Okta
  → engineer authenticates with corporate MFA
  → 4-hour AWS credential token is stored locally
  → AWS CLI and SDKs use token transparently
  → when token expires: runs aws sso login again
```

The engineer never sees or touches an `AWS_SECRET_ACCESS_KEY`. The token
cannot be used after it expires. If the engineer's laptop is stolen, the
token expires within hours and cannot be refreshed without authenticating
at the corporate identity provider — which security can immediately disable.

### How CI/CD systems are handled

GitHub Actions, GitLab CI, and Jenkins all support OpenID Connect (OIDC)
identity federation with AWS. Your CI/CD pipelines authenticate using a
short-lived token issued per-job with no stored secrets:

```yaml
# GitHub Actions example — no AWS credentials stored in GitHub
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789:role/GitHubActionsRole
    aws-region: us-east-1
```

Each pipeline run assumes a specific IAM role for the duration of the job.
The credential lasts minutes, not years. There are no secrets in GitHub to
rotate or accidentally expose.

---

## Implementation Roadmap

### Phase 1 — Parallel Setup (Weeks 1-2, zero downtime)

All existing access continues to work during this phase. Zero disruption.

- Enable IAM Identity Center in your AWS management account
- Connect Google Workspace or Okta as the identity provider (1-2 hours)
- Create Permission Sets mirroring current IAM user permissions
- Define access groups: Engineering-ReadOnly, Engineering-Developer,
  Engineering-Admin, SecurityTeam
- Assign groups to Permission Sets for each AWS account
- Engineers receive instructions to configure the SSO profile
- **No existing access is disabled**

### Phase 2 — Migration (Weeks 3-4)

Engineers update their CLI profiles and validate SSO access works for
their daily tasks.

- Engineers run `aws configure sso` and test their access
- Service workloads using IAM user keys are migrated to IAM roles:
  EC2 instance profiles, ECS task roles, Lambda execution roles
- CI/CD pipelines updated to use OIDC (GitHub Actions native support
  requires no third-party tooling)
- Run both authentication methods in parallel for 1-2 weeks

### Phase 3 — Decommission (Weeks 5-6)

- Disable all IAM user access keys (preserve users for audit history)
- Set IAM user console passwords to a cryptographically random value
  (preventing console login without deleting audit records)
- Configure automated quarterly access reviews in IAM Access Analyzer
- Set up automatic deprovisioning: engineers removed from Okta/Google
  automatically lose all AWS access within the sync interval (2-4 hours)
- Generate SOC 2 evidence: access review showing zero active long-lived keys

### Risk Mitigation

**Break-glass emergency access**

One IAM user is retained with a strong password and hardware MFA (YubiKey),
stored in a physical safe. This account is used only if the identity provider
is entirely unavailable. Every use generates an immediate CloudWatch alarm.
This is the same pattern used by AWS's own teams.

**Rollback procedure**

IAM users are disabled, not deleted. If SSO has an issue during migration,
re-enabling any IAM user is a two-minute console operation. This makes the
migration fully reversible until the decommission phase is complete.

**Gradual rollout**

By running both methods in parallel for two weeks, every engineer validates
that their SSO access works correctly before the old method is disabled.
No engineer should be surprised by a change that breaks their workflow.

---

## Cost-Benefit Analysis

### Direct Costs

| Item | Cost |
|------|------|
| IAM Identity Center | Free |
| Google Workspace / Okta integration | Included in existing subscription |
| Engineering implementation time | ~40 hours (one-time) |
| Ongoing maintenance | Negligible |

**Total additional AWS cost: $0.**

### Risk-Adjusted Benefits

| Benefit | Estimated Annual Value |
|---------|----------------------|
| Eliminate credential-rotation engineering time | ~2 hrs/engineer/year |
| SOC 2 audit prep reduction (4 controls automated) | ~20 hrs/audit cycle |
| Faster onboarding and offboarding | ~2 hrs/person lifecycle |
| Avoided cost of one leaked credential incident | $15,000 - $200,000 |

The ROI justification is primarily risk avoidance. A single exposed access key
that enables unauthorized production access carries costs — incident response,
potential data breach notification, regulatory exposure, and customer trust —
that dwarf the migration effort by two orders of magnitude.

For a company preparing for SOC 2 Type II certification, this is the single
highest-leverage security improvement available. It costs nothing in AWS fees,
completes within one quarter, and directly addresses the auditor's first line
of questioning.

---

## Recommendation

Approve Phase 1 to begin this week. The parallel setup carries zero risk:
all existing access continues unchanged while the team evaluates SSO in
parallel. The full migration completes in 6 weeks and will be complete well
before your SOC 2 Type II audit window.

**Immediate next steps:**

1. Confirm your identity provider (Google Workspace or Okta — both are
   supported with a 30-minute configuration)
2. Provide the list of current IAM users to define Permission Set mappings
3. Schedule a 2-hour setup session to complete Phase 1

This is the right move for security, for compliance, and for engineering
velocity. Long-lived access keys are a category of risk that can be eliminated
completely — this is one of the few places in security engineering where the
right answer is binary, not a tradeoff.

---

*Prepared by the Cloud Engineering team. Questions to: cloudteam@example.com*
