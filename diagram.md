# Task 2.2 — Preventive SCP Architecture

## Architecture Diagram — Policy Enforcement Points

```mermaid
flowchart TD
    ROOT["AWS Organizations Root\nManagement Account"]

    subgraph OUs["Organizational Units"]
        OU_PROD["OU: Production\nHighest restriction tier"]
        OU_DEV["OU: Development\nModerate restriction"]
        OU_SHARED["OU: Shared Services\nInfrastructure tier"]
        OU_SECURITY["OU: Security Tooling\nExempt from deny SCPs"]
    end

    subgraph SCPs["Service Control Policies"]
        SCP1["SCP: DenyPublicIngressRules\nBlocks 0.0.0.0/0 and ::/0"]
        SCP2["SCP: RequireApprovedRole\nOnly sg-change-approved role\ncan modify SGs in prod"]
        SCP3["SCP: RequireMFAForSG\nMFA required for all\nSG modifications"]
        SCP4["SCP: ProtectAuditInfra\nPrevents CloudTrail,\nConfig, GuardDuty deletion"]
    end

    subgraph WORKFLOW["Approved Change Workflow"]
        TICKET["1. Engineer files ticket\n(ServiceNow / Jira)"]
        REVIEW["2. Security team review\nand approval"]
        ASSUME["3. Assume sg-change-approved\nrole via STS"]
        APPLY["4. Apply change\n(SCP condition satisfied)"]
        LOG["5. CloudTrail event\n+ DynamoDB audit record"]
    end

    ROOT --> OU_PROD & OU_DEV & OU_SHARED & OU_SECURITY

    SCP1 --> OU_PROD & OU_DEV
    SCP2 --> OU_PROD
    SCP3 --> OU_PROD & OU_DEV
    SCP4 --> ROOT

    TICKET --> REVIEW --> ASSUME --> APPLY --> LOG

    style ROOT fill:#ede7f6,stroke:#4527a0,color:#311b92
    style SCP1 fill:#fce4ec,stroke:#c62828,color:#b71c1c
    style SCP2 fill:#e8eaf6,stroke:#283593,color:#1a237e
    style SCP3 fill:#fff8e1,stroke:#e65100,color:#bf360c
    style SCP4 fill:#e8f5e9,stroke:#1b5e20,color:#1b5e20
    style WORKFLOW fill:#f3e5f5,stroke:#6a1b9a,color:#4a148c
```

## Policy Enforcement Summary

| SCP | Applied To | Blocks | Allows Via |
|-----|-----------|--------|-----------|
| DenyPublicIngressRules | Prod + Dev OUs | 0.0.0.0/0 and ::/0 ingress | No exceptions — absolute deny |
| RequireApprovedRole | Production OU only | All SG changes from non-approved principals | Assumption of sg-change-approved role |
| RequireMFAForSG | Prod + Dev OUs | SG changes without MFA session | MFA-enabled sessions |
| ProtectAuditInfra | Root (all accounts) | Deletion of CloudTrail, Config, GuardDuty | SecurityTeamAdmin role only |
