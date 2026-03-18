
mermaid
graph TB
    subgraph AWS_ORG["AWS Organization — us-east-1"]
        direction TB

        subgraph HUB["Hub — Transit Gateway (tgw-hub-prod)"]
            TGW["Transit Gateway\nCentral BGP Router\n64512 ASN"]
            TGW_RT_PROD["TGW Route Table\nProduction"]
            TGW_RT_DEV["TGW Route Table\nDevelopment"]
            TGW_RT_SHARED["TGW Route Table\nShared Services"]
            TGW --- TGW_RT_PROD
            TGW --- TGW_RT_DEV
            TGW --- TGW_RT_SHARED
        end

        subgraph INSPECT["Inspection VPC — 10.0.0.0/24 (Security Hub)"]
            direction LR
            FIREWALL["AWS Network Firewall\nIDS/IPS · DPI · TLS Inspection"]
            WAF_INSPECT["WAF Rules Engine\nOWASP Top 10"]
            FIREWALL --> WAF_INSPECT
        end

        subgraph PROD["Production VPC — 10.1.0.0/16"]
            direction TB
            PROD_PUB["Public Subnet\n10.1.0.0/24\nAZ-a and AZ-b"]
            PROD_APP["App Subnet\n10.1.1.0/24\nPrivate · No IGW"]
            PROD_DB["DB Subnet\n10.1.2.0/24\nIsolated · RDS/Aurora"]
            PROD_PUB --> PROD_APP --> PROD_DB
        end

        subgraph DEV["Development VPC — 10.2.0.0/16"]
            direction TB
            DEV_APP["Dev App Subnet\n10.2.1.0/24"]
            DEV_SANDBOX["Sandbox Subnet\n10.2.2.0/24\nNo prod access"]
            DEV_APP --> DEV_SANDBOX
        end

        subgraph SHARED["Shared Services VPC — 10.3.0.0/16"]
            direction TB
            DNS["Route 53 Resolver\nCentralized DNS"]
            MONITOR["Monitoring Stack\nCloudWatch · Prometheus"]
            SECRETS["Secrets Manager\nSSM Parameter Store"]
        end

        subgraph EGRESS["Egress VPC — 10.4.0.0/24"]
            NAT["NAT Gateway\nCentralized Internet Egress"]
            EGRESS_FW["Egress Firewall\nDomain Allow-list"]
            NAT --> EGRESS_FW
        end

        subgraph INGRESS["Ingress VPC — 10.5.0.0/24"]
            ALB["Application Load Balancer\nPublic Entry Point"]
            SHIELD["AWS Shield Advanced\nDDoS Protection"]
            ALB --> SHIELD
        end

        INTERNET(("Internet"))
    end

    TGW <-->|"Attachment + Route Table"| INSPECT
    TGW <-->|"Attachment + Route Table"| PROD
    TGW <-->|"Attachment + Route Table"| DEV
    TGW <-->|"Attachment + Route Table"| SHARED
    TGW <-->|"Attachment + Route Table"| EGRESS
    TGW <-->|"Attachment + Route Table"| INGRESS

    INTERNET -->|"Inbound traffic"| ALB
    NAT -->|"Outbound only"| INTERNET
    FIREWALL -.->|"All traffic inspected"| TGW

    style AWS_ORG fill:#f0f4ff,stroke:#4a6fa5,stroke-width:2px
    style HUB fill:#e8eaf6,stroke:#5c6bc0,stroke-width:2px
    style INSPECT fill:#fce4ec,stroke:#e91e63,stroke-width:2px
    style PROD fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    style DEV fill:#e0f2f1,stroke:#00695c,stroke-width:2px
    style SHARED fill:#fff8e1,stroke:#f57f17,stroke-width:2px
    style EGRESS fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style INGRESS fill:#fbe9e7,stroke:#bf360c,stroke-width:2px
```

---
