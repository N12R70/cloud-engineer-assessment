

---

## Prompting Strategy Commentary

My approach to this assessment was to decompose each task before writing any
prompt, identify the specific output format required, and prompt for one
deliverable at a time rather than asking for everything at once.

Key principles I followed:

1. **Architecture before code.** For each part, I first established the design
   (diagram) before asking for implementation (Terraform). This avoided
   generating code for a design I hadn't validated.

2. **Format constraints in the prompt.** I included the exact requirements —
   minimum line counts, output formats, word limits — in each prompt so the AI
   was working toward the same spec the assessors would evaluate against.

3. **Self-critique iteration.** For Task 1.3, I explicitly asked the AI to
   critique its own output, then wrote my personal analysis identifying what
   it missed. This is more honest than asking for a critique without disclosing
   that the AI was critiquing its own work.

4. **Validation mindset.** I reviewed every Terraform resource block against
   the AWS provider documentation for the specific resource type, particularly
   SCP content syntax and IAM condition keys.

---

## Complete Interaction Transcript

### Session 1 — Part 1, Task 1.1

**My prompt:**

"I'm completing a cloud engineer technical assessment. Task 1.1 asks me to
generate a Mermaid.js diagram for an AWS Hub-and-Spoke network topology.
Requirements: Central Transit Gateway connecting multiple VPCs, dedicated
Inspection VPC with traffic filtering, minimum 3 spoke VPCs (Production,
Development, Shared Services), appropriate routing and security zones.
Generate the complete Mermaid.js code that will render in mermaid.live."

**Claude's response:**

[Claude generated the hub-and-spoke Mermaid.js diagram with Transit Gateway
as the central hub, six spoke VPCs (Inspection, Production, Development,
Shared Services, Egress, Ingress), and bidirectional TGW attachment arrows.
The diagram used subgraph notation to show VPC internals including subnet tiers
within Production and service components within each VPC.]

**My follow-up prompt:**

"Good. Now I have the diagram. Using this as input, generate the technical
documentation for Task 1.2. Requirements: 2-3 pages, markdown format.
Cover: architecture overview and design rationale, network segmentation
strategy, traffic flow patterns (north-south and east-west), security
controls and isolation boundaries, scalability considerations."

**Claude's response:**

[Claude generated the full technical documentation covering all five required
sections with a VPC inventory table, security zone definitions with TGW route
table logic, traffic flow diagrams in ASCII, security controls table, and
scalability guidance for multi-account and multi-region expansion.]

---

### Session 2 — Part 1, Task 1.3

**My prompt:**

"Now perform a critical analysis of the hub-and-spoke architecture from Task
1.1. Specifically identify: single points of failure, availability zone
considerations, failure domain isolation, disaster recovery gaps, cost
optimization opportunities. Format the output as a structured critique I
can include as 'Part A: AI Critique Output' in my Task 1.3 deliverable."

**Claude's response:**

[Claude generated the architecture critique identifying: TGW as a potential
SPOF, Inspection VPC as a traffic chokepoint requiring multi-AZ Network
Firewall endpoints, single NAT Gateway AZ risk, missing multi-AZ documentation
for ALB/NAT/RDS/Firewall, failure domain concerns from single TGW, DR gaps
(no cross-region, no tested runbook), and cost optimization table.]

**My follow-up prompt:**

"This is the AI critique. Now I need to write my own analysis as 'Part B'.
Help me structure a 500-750 word analysis that: agrees or disagrees with
specific AI points and explains why, identifies what the AI missed, and
states what I would prioritize fixing first and why."

**Claude's response:**

[Claude provided a structured analysis framework. I then wrote the actual
Part B content based on this framework, adding my own perspective on what
was missed — specifically the IAM/cross-account permission model gap, DNS
security concerns, IaC automation risk on route tables, and the missing cost
model for the inspection tier.]

---

### Session 3 — Part 2, Task 2.1

**My prompt:**

"Task 2.1: Design and implement a reactive remediation system for AWS security
group drift. Requirements: detects unauthorized SG rule changes, automatically
reverts non-compliant modifications, logs all drift events for audit trails,
notifies security team of violations. Deliverable 1: Mermaid.js architecture
diagram. Deliverable 2: Terraform code snippet (minimum 50 lines) implementing
core detection/remediation logic."

**Claude's response:**

[Claude generated the EventBridge + Lambda + DynamoDB + SNS architecture
diagram in Mermaid.js, followed by Terraform code creating: DynamoDB audit
table with PITR and SSE, SNS topic with KMS encryption, IAM role with
least-privilege policy, Lambda function, EventBridge rule on
AuthorizeSecurityGroupIngress events, and CloudWatch alarm on Lambda errors.]

**My follow-up prompt:**

"Good. Now generate the Lambda function Python code. It should: evaluate
each CIDR in the new SG rule, revoke non-compliant rules using
ec2:RevokeSecurityGroupIngress, write audit records to DynamoDB including
event metadata, and publish SNS alerts with structured JSON. Handle both
IPv4 and IPv6. Handle partial remediation failures."

**Claude's response:**

[Claude generated the full Python Lambda handler with structured logging,
separate functions for CIDR evaluation, rule revocation, DynamoDB audit
record writing, and SNS alert publishing. The code handles both IPv4 and
IPv6 ranges, tracks remediation success per-rule, and includes appropriate
error handling with CLIENT_ERROR catching.]

---

### Session 4 — Part 2, Task 2.2

**My prompt:**

"Task 2.2: Design a preventive architecture using AWS Service Control Policies
(SCPs) and infrastructure guardrails. Requirements: prevents unauthorized SG
modifications at org level, implements least-privilege, allows legitimate
changes through approved workflows, scales across 50+ accounts. Deliverable:
Mermaid.js diagram showing policy enforcement points, Terraform SCP
implementation (minimum 50 lines), strategy document (400-500 words)."

**Claude's response:**

[Claude generated: Mermaid flowchart showing Organizations root → OUs → SCPs
with an approved change workflow sidebar, Terraform creating four SCPs
(DenyPublicIngress, RequireApprovedRole, RequireMFA, ProtectAuditInfra)
with OU attachments and the sg-change-approved IAM role with ExternalId
and MFA conditions, and a strategy document covering automatic scale to
50+ accounts, the approved-role model as governance, and measurable outcomes.]

---

### Session 5 — Part 3

**My prompt:**

"Task 3: Write a client-facing technical proposal for a CTO of a Series A
SaaS company preparing for SOC 2 Type II. They use IAM users with long-lived
access keys. Convince them to migrate to AWS IAM Identity Center. Target:
CTO with strong technical background, limited AWS expertise. Must include:
executive summary with business impact, technical comparison (IAM users vs
Identity Center), implementation roadmap with risk mitigation, cost-benefit
analysis. 2-3 pages, professional markdown format."

**Claude's response:**

[Claude generated the full client proposal covering: executive summary with
three key numbers, problem statement explaining long-lived key risks in
business language, solution section with technical comparison table and
flow diagram, six-week implementation roadmap with three phases, break-glass
emergency access plan, and cost-benefit analysis with risk-adjusted values.]

---

## Validation Steps Taken

After each AI-generated output, I validated:

**Mermaid.js diagrams:** Tested each code block in mermaid.live to confirm
rendering without syntax errors.

**Terraform code:** Reviewed IAM condition keys (`ec2:cidrBlock`,
`aws:PrincipalArn`, `aws:MultiFactorAuthPresent`) against AWS documentation
for correct syntax. Verified SCP content structure against the Organizations
API specification.

**Python Lambda:** Traced through the logic for both compliant and non-compliant
cases, including the partial remediation failure path, to confirm the audit
record and SNS payload would be correct in each case.

