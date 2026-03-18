# Compliance Foundry — Cloud Engineer Technical Assessment

**Candidate:** Cloud Engineer Applicant  
**Position:** IC4/IC5 Cloud Engineer  
**Company:** Compliance Foundry  
**Date:** 2026-03-18  
**Time Spent:** ~5 hours

---

## Repository Structure

```
compliance-foundry-assessment/
├── README.md                              ← this file
├── part1/
│   ├── task1-1-network-diagram.md         ← Mermaid.js hub-and-spoke diagram
│   ├── task1-2-technical-docs.md          ← Architecture documentation (2-3 pages)
│   └── task1-3-architecture-critique.md   ← AI critique + personal analysis
├── part2/
│   ├── task2-1/                           ← Reactive remediation system
│   │   ├── diagram.md                     ← Mermaid.js architecture diagram
│   │   ├── main.tf                        ← Terraform: EventBridge + Lambda + DynamoDB
│   │   ├── lambda/index.py                ← Python Lambda function
│   │   └── explanation.md                 ← System stability explanation
│   └── task2-2/                           ← Preventive SCP architecture
│       ├── diagram.md                     ← Mermaid.js policy enforcement diagram
│       ├── main.tf                        ← Terraform: SCPs + IAM roles
│       └── strategy.md                    ← Infrastructure strategy document
├── part3/
│   └── iam-identity-center-proposal.md    ← Client-facing technical proposal
└── ai-transcript/
    └── transcript.md                      ← Complete AI interaction transcript
```

---

## Assumptions Made

1. **AWS Region:** All resources deploy to `us-east-1` unless otherwise specified.
2. **Identity Provider (Part 3):** Assumed Google Workspace as the corporate IdP; Okta steps are equivalent.
3. **Allowed CIDRs (Part 2.1):** RFC 1918 private ranges `10.0.0.0/8` and `172.16.0.0/12` are compliant.
4. **TGW Route Tables:** One per environment tier (prod, dev, shared) for maximum isolation.
5. **Inspection VPC:** AWS Network Firewall used as the inspection engine.
6. **SCP scope:** Applied at OU level, not root, to allow management account flexibility.
7. **Break-glass account:** One IAM user with hardware MFA retained post-migration for emergency access.

---

## How to Use the Mermaid Diagrams

All diagrams are in Mermaid.js format. To render them:

1. Visit [mermaid.live](https://mermaid.live)
2. Copy the code block contents from any `diagram.md` file
3. Paste into the editor — the diagram renders immediately on the right

Alternatively, GitHub renders Mermaid natively in markdown files (just view the file on github.com).

---

## Prompting Strategy

See `ai-transcript/transcript.md` for the complete AI interaction. My approach:

- **Decomposed the assessment** into independent tasks before prompting
- **Architecture first, then code** — got the diagram right before writing Terraform
- **Iterated on critique** — asked the AI to critique its own output, then added my own analysis of gaps
- **Validated Terraform** — checked IAM conditions and SCP syntax against AWS documentation
- **Kept prompts specific** — included exact requirements (line minimums, output formats) in each prompt
