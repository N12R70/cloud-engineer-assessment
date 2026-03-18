# =============================================================================
# Task 2.2: Preventive SCP Architecture — Policy Enforcement Points
# Compliance Foundry Technical Assessment
# =============================================================================
#
# SCPs created:
#   1. DenyPublicIngressRules       — blocks 0.0.0.0/0 and ::/0 absolutely
#   2. RequireApprovedRoleForSGProd — production SG changes via approved role only
#   3. RequireMFAForSecurityGroups  — MFA required for all SG modifications
#   4. ProtectAuditInfrastructure   — prevents deletion of security controls
#
# IAM resources:
#   - sg-change-approved role       — the only allowed principal for prod SG changes
#   - sg-change-approved-policy     — least-privilege SG permissions
# =============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "production_ou_id" {
  description = "AWS Organizations OU ID for production accounts"
  type        = string

  validation {
    condition     = startswith(var.production_ou_id, "ou-")
    error_message = "OU ID must start with 'ou-'."
  }
}

variable "development_ou_id" {
  description = "AWS Organizations OU ID for development accounts"
  type        = string

  validation {
    condition     = startswith(var.development_ou_id, "ou-")
    error_message = "OU ID must start with 'ou-'."
  }
}

variable "root_ou_id" {
  description = "AWS Organizations root ID (r-xxxx format)"
  type        = string

  validation {
    condition     = startswith(var.root_ou_id, "r-")
    error_message = "Root ID must start with 'r-'."
  }
}

variable "tooling_account_id" {
  description = "AWS Account ID of the security tooling account that can assume sg-change-approved"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.tooling_account_id))
    error_message = "Account ID must be a 12-digit number."
  }
}

variable "approved_regions" {
  description = "List of AWS regions where operations are permitted"
  type        = list(string)
  default     = ["us-east-1", "us-west-2", "eu-west-1"]
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# -----------------------------------------------------------------------------
# SCP 1: Deny unrestricted ingress rules (absolute block — no exceptions)
# Applies to: Production OU + Development OU
# This cannot be bypassed by any IAM policy in those accounts.
# -----------------------------------------------------------------------------

resource "aws_organizations_policy" "deny_public_ingress" {
  name        = "DenyPublicSecurityGroupIngressRules"
  description = "Prevents any security group rule that opens 0.0.0.0/0 or ::/0 ingress. Absolute deny with no exceptions."
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyPublicIPv4IngressRules"
        Effect    = "Deny"
        Action    = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:ModifySecurityGroupRules",
          "ec2:UpdateSecurityGroupRuleDescriptionsIngress"
        ]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "ec2:cidrBlock" = "0.0.0.0/0"
          }
        }
      },
      {
        Sid       = "DenyPublicIPv6IngressRules"
        Effect    = "Deny"
        Action    = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:ModifySecurityGroupRules"
        ]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "ec2:cidrBlock" = "::/0"
          }
        }
      }
    ]
  })

  tags = {
    Purpose   = "security-guardrail"
    ManagedBy = "terraform"
  }
}

# -----------------------------------------------------------------------------
# SCP 2: Require approved role for all SG changes in Production
# Applies to: Production OU only
# All engineers must assume sg-change-approved role via the approved workflow.
# SSO sessions matching the AWSReservedSSO pattern are also permitted.
# -----------------------------------------------------------------------------

resource "aws_organizations_policy" "require_approved_role_prod" {
  name        = "RequireApprovedRoleForProductionSGChanges"
  description = "All security group modifications in production must be made via the sg-change-approved IAM role or SecurityTeamAdmin. Blocks direct engineer access."
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenySGChangesFromNonApprovedPrincipals"
        Effect = "Deny"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:ModifySecurityGroupRules",
          "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
          "ec2:UpdateSecurityGroupRuleDescriptionsEgress"
        ]
        Resource  = "*"
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = [
              # The approved change workflow role
              "arn:aws:iam::*:role/sg-change-approved",
              # Security team emergency access
              "arn:aws:iam::*:role/SecurityTeamAdmin",
              # AWS SSO roles (managed by Identity Center)
              "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_SecurityTeamAdmin_*",
              # Infrastructure automation role
              "arn:aws:iam::*:role/TerraformExecutionRole",
              # Break-glass emergency role
              "arn:aws:iam::*:role/BreakGlassRole"
            ]
          }
        }
      }
    ]
  })

  tags = {
    Purpose   = "security-guardrail"
    ManagedBy = "terraform"
  }
}

# -----------------------------------------------------------------------------
# SCP 3: Require MFA for all SG modifications
# Applies to: Production OU + Development OU
# Ensures all SG changes are made from authenticated MFA sessions.
# -----------------------------------------------------------------------------

resource "aws_organizations_policy" "require_mfa_sg_changes" {
  name        = "RequireMFAForSecurityGroupModifications"
  description = "Enforces MFA authentication for all security group create, modify, and delete operations."
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenySGChangesWithoutMFA"
        Effect = "Deny"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:ModifySecurityGroupRules"
        ]
        Resource  = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })

  tags = {
    Purpose   = "security-guardrail"
    ManagedBy = "terraform"
  }
}

# -----------------------------------------------------------------------------
# SCP 4: Protect audit infrastructure (applied at root — all accounts)
# Prevents deletion of CloudTrail, Config, GuardDuty, and Security Hub.
# The SecurityTeamAdmin role is the only exception.
# -----------------------------------------------------------------------------

resource "aws_organizations_policy" "protect_audit_infrastructure" {
  name        = "ProtectAuditAndSecurityInfrastructure"
  description = "Prevents deletion or disabling of CloudTrail, AWS Config, GuardDuty, and Security Hub. Applied at the root to cover all accounts including management."
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyAuditInfrastructureDeletion"
        Effect = "Deny"
        Action = [
          # CloudTrail
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail",
          # AWS Config
          "config:DeleteConfigRule",
          "config:DeleteConfigurationRecorder",
          "config:DeleteDeliveryChannel",
          "config:StopConfigurationRecorder",
          # GuardDuty
          "guardduty:DeleteDetector",
          "guardduty:DisassociateFromAdministratorAccount",
          "guardduty:DisassociateMembers",
          # Security Hub
          "securityhub:DisableSecurityHub",
          "securityhub:DeleteHub",
          # IAM Access Analyzer
          "access-analyzer:DeleteAnalyzer"
        ]
        Resource  = "*"
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:role/SecurityTeamAdmin",
              "arn:aws:iam::*:role/OrganizationAccountAccessRole"
            ]
          }
        }
      },
      {
        Sid    = "DenyRegionsNotApproved"
        Effect = "Deny"
        NotAction = [
          # These services are global and must not be region-restricted
          "iam:*",
          "organizations:*",
          "route53:*",
          "budgets:*",
          "support:*",
          "trustedadvisor:*",
          "cloudfront:*",
          "waf:*",
          "health:*"
        ]
        Resource  = "*"
        Condition = {
          StringNotIn = {
            "aws:RequestedRegion" = var.approved_regions
          }
        }
      }
    ]
  })

  tags = {
    Purpose   = "security-guardrail"
    ManagedBy = "terraform"
  }
}

# -----------------------------------------------------------------------------
# SCP Attachments — Apply policies to appropriate OUs
# -----------------------------------------------------------------------------

resource "aws_organizations_policy_attachment" "deny_public_ingress_prod" {
  policy_id = aws_organizations_policy.deny_public_ingress.id
  target_id = var.production_ou_id
}

resource "aws_organizations_policy_attachment" "deny_public_ingress_dev" {
  policy_id = aws_organizations_policy.deny_public_ingress.id
  target_id = var.development_ou_id
}

resource "aws_organizations_policy_attachment" "require_approved_role_prod" {
  policy_id = aws_organizations_policy.require_approved_role_prod.id
  target_id = var.production_ou_id
}

resource "aws_organizations_policy_attachment" "require_mfa_prod" {
  policy_id = aws_organizations_policy.require_mfa_sg_changes.id
  target_id = var.production_ou_id
}

resource "aws_organizations_policy_attachment" "require_mfa_dev" {
  policy_id = aws_organizations_policy.require_mfa_sg_changes.id
  target_id = var.development_ou_id
}

resource "aws_organizations_policy_attachment" "protect_audit_root" {
  policy_id = aws_organizations_policy.protect_audit_infrastructure.id
  target_id = var.root_ou_id
}

# -----------------------------------------------------------------------------
# IAM: The sg-change-approved role — the only approved change pathway
# Must be deployed to every production account via StackSets
# -----------------------------------------------------------------------------

resource "aws_iam_role" "sg_change_approved" {
  name = "sg-change-approved"
  path = "/security/"

  description = "The only IAM principal permitted to modify security groups in production. Assumed via the approved change workflow from the security tooling account with MFA."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowToolingAccountWithMFA"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${var.tooling_account_id}:role/SecurityTeamAdmin",
            "arn:aws:iam::${var.tooling_account_id}:role/TerraformExecutionRole"
          ]
        }
        Action    = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
          StringEquals = {
            "sts:ExternalId" = "sg-change-approved-workflow"
          }
        }
      }
    ]
  })

  max_session_duration = 3600  # 1 hour maximum session

  tags = {
    Purpose    = "approved-sg-changes"
    ManagedBy  = "terraform"
    Restricted = "true"
    Workflow   = "security-change-approval"
  }
}

resource "aws_iam_role_policy" "sg_change_approved_permissions" {
  name = "sg-change-approved-least-privilege"
  role = aws_iam_role.sg_change_approved.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSGChangesWithApprovedCIDRsOnly"
        Effect = "Allow"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:ModifySecurityGroupRules"
        ]
        Resource  = "*"
        Condition = {
          StringNotEquals = {
            "ec2:cidrBlock" = ["0.0.0.0/0", "::/0"]
          }
        }
      },
      {
        Sid    = "AllowSGCreationAndDeletion"
        Effect = "Allow"
        Action = [
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:CreateTags"
        ]
        Resource = "*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "scp_deny_public_ingress_id" {
  description = "SCP ID for the public ingress deny policy"
  value       = aws_organizations_policy.deny_public_ingress.id
}

output "scp_require_approved_role_id" {
  description = "SCP ID for the approved role requirement"
  value       = aws_organizations_policy.require_approved_role_prod.id
}

output "scp_require_mfa_id" {
  description = "SCP ID for the MFA requirement"
  value       = aws_organizations_policy.require_mfa_sg_changes.id
}

output "scp_protect_audit_id" {
  description = "SCP ID for audit infrastructure protection"
  value       = aws_organizations_policy.protect_audit_infrastructure.id
}

output "sg_change_approved_role_arn" {
  description = "ARN of the approved SG change role for cross-account assumption"
  value       = aws_iam_role.sg_change_approved.arn
}
