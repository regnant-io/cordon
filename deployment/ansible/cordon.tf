# Cordon v2.0 — Terraform: Sovereign Cloud Deployment
# Deploys a Cordon node inside the client's own VPC.
# Requires: AMD EPYC instances with SEV-SNP support (e.g., AWS c6a, Azure DCsv3)

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ─── Variables ────────────────────────────────────────────────────────────────

variable "deployment_id" {
  description = "Unique deployment identifier (used in key derivation — never change)"
  type        = string
}

variable "node_id" {
  description = "Node identifier"
  type        = string
  default     = "cordon-node-001"
}

variable "vpc_id" {
  description = "Client VPC ID"
  type        = string
}

variable "subnet_id" {
  description = "Subnet for Cordon node (private subnet recommended)"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type (must support AMD SEV-SNP)"
  type        = string
  default     = "c6a.4xlarge"  # AMD EPYC — SEV-SNP capable
}

variable "cordon_version" {
  description = "Cordon version to deploy"
  type        = string
  default     = "2.0.0"
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to reach Cordon API"
  type        = list(string)
}

variable "key_name" {
  description = "EC2 key pair name for emergency access"
  type        = string
}

# ─── Security Group ───────────────────────────────────────────────────────────

resource "aws_security_group" "cordon" {
  name_prefix = "cordon-${var.node_id}-"
  vpc_id      = var.vpc_id
  description = "Cordon node: inbound API only, zero egress"

  # Inbound: API port from allowed CIDRs only
  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "Cordon API (mTLS)"
  }

  # Inbound: SSH for emergency operator access (restrict to bastion CIDR)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "SSH emergency access"
  }

  # Outbound: ZERO EGRESS
  # No egress rules = all outbound blocked by default
  # This is the software-level zero-egress control.
  # A hardware firewall appliance is the authoritative control per §4.1.

  tags = {
    Name       = "cordon-${var.node_id}"
    ManagedBy  = "terraform"
    Cordon    = "true"
    ZeroEgress = "true"
  }
}

# ─── IAM Role (minimal) ───────────────────────────────────────────────────────

resource "aws_iam_role" "cordon" {
  name_prefix = "cordon-${var.node_id}-"
  description = "Cordon node IAM role (minimal — KMS only)"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = {
    Name    = "cordon-${var.node_id}"
    Cordon = "true"
  }
}

resource "aws_iam_instance_profile" "cordon" {
  name_prefix = "cordon-${var.node_id}-"
  role        = aws_iam_role.cordon.name
}

# ─── EC2 Instance ─────────────────────────────────────────────────────────────

data "aws_ami" "ubuntu_amd64" {
  most_recent = true
  owners      = ["099720109477"]  # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "cordon" {
  ami                    = data.aws_ami.ubuntu_amd64.id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.cordon.id]
  iam_instance_profile   = aws_iam_instance_profile.cordon.name
  key_name               = var.key_name

  # ECC memory — mandatory per spec §6.1
  # Note: verify instance type supports ECC (all server-grade AMD EPYC do)

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 100
    encrypted             = true  # Encryption at rest
    delete_on_termination = true
  }

  # Model weights volume (encrypted)
  ebs_block_device {
    device_name           = "/dev/sdb"
    volume_type           = "gp3"
    volume_size           = 500
    encrypted             = true
    delete_on_termination = false  # Persist across reboots
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh.tpl", {
    cordon_version = var.cordon_version
    deployment_id   = var.deployment_id
    node_id         = var.node_id
  }))

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 mandatory
    http_put_response_hop_limit = 1
  }

  monitoring = true  # CloudWatch detailed monitoring

  tags = {
    Name           = "cordon-${var.node_id}"
    CordonVersion = var.cordon_version
    DeploymentId   = var.deployment_id
    ManagedBy      = "terraform"
  }

  lifecycle {
    ignore_changes = [ami]  # Don't recreate on AMI update — use Cordon update pipeline
  }
}

# ─── Outputs ──────────────────────────────────────────────────────────────────

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.cordon.id
}

output "private_ip" {
  description = "Private IP address of Cordon node"
  value       = aws_instance.cordon.private_ip
}

output "api_endpoint" {
  description = "Cordon API endpoint (private)"
  value       = "https://${aws_instance.cordon.private_ip}:8443"
}

output "security_group_id" {
  description = "Security group ID (for adding your application servers)"
  value       = aws_security_group.cordon.id
}
