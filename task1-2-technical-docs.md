# AWS Hub-and-Spoke Network Architecture
## Technical Documentation

**Document version:** 1.0  
**Author:** Cloud Engineering Team  
**Date:** 2026-03-18  
**Classification:** Internal — Compliance Foundry Assessment

---

## 1. Architecture Overview & Design Rationale

This document describes a hub-and-spoke network topology deployed on AWS,
using AWS Transit Gateway (TGW) as the central routing hub. The design
centralizes network inspection, egress, and shared services while keeping
workload VPCs isolated from one another by default.

### Why Hub-and-Spoke?

Before this architecture, point-to-point VPC peering at scale creates an
unmanageable mesh: N*(N-1)/2 connections. With 10 VPCs, that is 45 peering
connections. With 50 VPCs it is 1,225. Transit Gateway reduces this to N
connections — one per VPC — while a central route table controls which VPCs
can communicate.

The hub-and-spoke model provides three core properties:

- **Operational simplicity:** one place to manage routing policy across the
  entire organization
- **Security enforcement:** all inter-VPC traffic passes through a single
  inspection chokepoint
- **Scalability:** adding a new spoke VPC requires one TGW attachment, not N
  new peering connections

### VPC Inventory

| VPC | CIDR | Purpose | Internet Access |
|-----|------|---------|----------------|
| Inspection | 10.0.0.0/24 | Network Firewall, IDS/IPS, WAF | None |
| Production | 10.1.0.0/16 | Live workloads, customer data | Via Egress VPC only |
| Development | 10.2.0.0/16 | Engineering environments | Via Egress VPC (filtered) |
| Shared Services | 10.3.0.0/16 | DNS, monitoring, secrets | None |
| Egress | 10.4.0.0/24 | Centralized NAT Gateway | Outbound only |
| Ingress | 10.5.0.0/24 | ALB, WAF, Shield Advanced | Inbound only |

---

## 2. Network Segmentation Strategy

### Security Zones

The architecture enforces three security zones using TGW route tables. Each
TGW route table acts as a firewall at the routing layer — before any packet
reaches a Security Group.

**Zone A — Production (highest trust)**

The Production TGW route table propagates routes only from Shared Services
and Ingress VPCs. It has no route to Development, preventing lateral movement
from a compromised dev environment to production workloads.

**Zone B — Development (medium trust)**

The Development route table propagates routes to Shared Services (for DNS and
secrets) but has no route to Production. Developers can reach shared
infrastructure but never production.

**Zone C — Shared Services (infrastructure tier)**

Reachable from all spoke VPCs but its outbound routes are limited to
infrastructure-specific destinations only. It provides DNS, monitoring, and
secret delivery — it does not receive arbitrary application traffic.

### Subnet Isolation within Production VPC

The Production VPC enforces a three-tier architecture with Security Groups
that reference each other by Group ID:

```
Internet → ALB (public subnet)
         → App Layer (private subnet) [only accepts traffic from ALB SG]
         → DB Layer (isolated subnet)  [only accepts traffic from App SG]
```

This means the database tier is unreachable from anything except the
application tier, regardless of what other resources exist in the account.

### TGW Route Table Summary

| Route Table | Allows routes from | Blocks routes to |
|-------------|-------------------|-----------------|
| Production RT | Shared Services, Ingress | Development, Egress (direct) |
| Development RT | Shared Services, Egress | Production |
| Shared Services RT | All VPCs (receive only) | Workload subnets |

---

## 3. Traffic Flow Patterns

### North-South Traffic (Internet to/from Workloads)

**Inbound flow:**

```
Internet
  → Ingress VPC (Shield Advanced DDoS protection)
  → Application Load Balancer + WAF (OWASP Top 10 filtering)
  → Transit Gateway
  → Inspection VPC (AWS Network Firewall: IDS/IPS, TLS inspection)
  → Transit Gateway
  → Production VPC — App subnet
```

Every packet from the internet traverses two inspection layers before
reaching any workload: WAF at the edge for application-layer filtering,
and Network Firewall for deep packet inspection and intrusion detection.

**Outbound flow:**

```
Production VPC
  → Transit Gateway
  → Egress VPC (domain allow-list firewall)
  → NAT Gateway
  → Internet
```

Outbound traffic is restricted to an allow-list of approved domains. Any
destination not explicitly permitted is blocked, preventing data exfiltration
through unexpected channels.

### East-West Traffic (VPC to VPC)

East-west traffic always traverses the TGW. TGW route tables determine
which VPCs can communicate before any Security Group evaluation occurs.

For sensitive east-west flows (e.g., Production to Shared Services), traffic
optionally routes through the Inspection VPC for logging and anomaly
detection. This is configured per-flow using TGW routing policy.

All east-west traffic is encrypted in transit using TLS 1.2+ enforced at
the application layer.

---

## 4. Security Controls & Isolation Boundaries

| Control Layer | Implementation | Coverage |
|--------------|----------------|---------|
| DDoS protection | AWS Shield Advanced | All inbound at Ingress VPC |
| Application filtering | AWS WAF (OWASP Top 10 managed rules) | All HTTP/S inbound |
| Deep packet inspection | AWS Network Firewall (IDS/IPS mode) | North-south and east-west |
| Egress control | Domain allow-list in Egress VPC firewall | All outbound to internet |
| Routing isolation | TGW Route Tables per environment | Inter-VPC routing |
| Instance isolation | Security Groups (ID-referenced, not CIDR) | Within VPCs |
| Encryption in transit | TLS 1.2+ enforced via ALB policy | All application traffic |
| Secrets delivery | AWS Secrets Manager via Shared Services VPC | All workload VPCs |
| Threat detection | Amazon GuardDuty | Organization-wide |
| Audit logging | VPC Flow Logs to S3, queried via Athena | All VPCs |
| Configuration compliance | AWS Config with auto-remediation | All accounts |

### Isolation Guarantees

1. **Production workloads cannot be reached directly from the internet** — the
   Production VPC has no Internet Gateway. All inbound traffic must transit
   through the Ingress VPC and Inspection VPC first.

2. **Development engineers cannot access production** — TGW route tables have
   no Dev-to-Production route. This is enforced at Layer 3, below any
   application or Security Group control.

3. **Data cannot leave to unapproved destinations** — the Egress VPC's domain
   allow-list firewall blocks all outbound traffic not explicitly permitted,
   even from compromised workloads.

---

## 5. Scalability Considerations

### Adding a New Spoke VPC

Adding any new workload VPC requires exactly four steps:

1. Create the VPC and subnets (Terraform module call)
2. Create TGW attachment (`aws_ec2_transit_gateway_vpc_attachment`)
3. Associate the appropriate TGW route table for the environment tier
4. Update Security Group references if cross-VPC access is required

This process is fully automated via Terraform and completes in under
5 minutes. No existing VPCs or route tables are modified.

### Multi-Account Scaling

In an AWS Organizations deployment, the TGW is shared to spoke accounts via
AWS Resource Access Manager (RAM). Each environment (production, development,
staging) lives in a separate AWS account. The TGW remains in the networking
account and maintains centralized routing control without cross-account
credential sharing.

This model supports hundreds of spoke VPCs across dozens of accounts with no
fundamental architectural changes.

### Traffic Throughput

AWS Transit Gateway supports up to 50 Gbps per availability zone with burst
capability. For workloads approaching this limit, ECMP (Equal-Cost Multi-Path)
routing across multiple TGW attachments linearly increases throughput. AWS
Network Firewall scales automatically and supports up to 100 Gbps.

### Multi-Region Expansion

TGW inter-region peering connects regional hubs without traversing the public
internet. The spoke VPC pattern replicates into a secondary region with Route
53 routing policies directing traffic based on latency or health checks. A
single global Transit Gateway mesh can span all commercial AWS regions.

---

## 6. Operational Runbook References

| Procedure | Owner | Documentation |
|-----------|-------|---------------|
| Adding a new spoke VPC | Platform Engineering | `runbooks/add-spoke-vpc.md` |
| Updating firewall rules | Security Engineering | `runbooks/update-firewall-rules.md` |
| Investigating Flow Log anomalies | Security Operations | `runbooks/flow-log-investigation.md` |
| TGW route table modification | Platform Engineering | `runbooks/tgw-route-changes.md` |
| Egress allow-list updates | Security Engineering | `runbooks/egress-allowlist.md` |

---

*Document maintained by the Platform Engineering team. Review quarterly or
after any significant architecture change.*
