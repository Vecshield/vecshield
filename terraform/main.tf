# VecShield Enterprise — example Terraform scaffold.
#
# This is a STARTING POINT, not a production module. It documents the shape of a
# customer-hosted deployment (compute + secret + storage) so you can adapt it to
# your cloud and landing zone. No cloud provider is hard-coded.

terraform {
  required_version = ">= 1.5"
  # required_providers { aws = { source = "hashicorp/aws" } }  # example
}

variable "image" {
  description = "Container image ref for vecshield-platform (private registry)."
  type        = string
  default     = "your-registry.example/vecshield-platform:0.0.1"
}

variable "api_token" {
  description = "Bearer token required by the VecShield Enterprise API."
  type        = string
  sensitive   = true
}

variable "port" {
  description = "API/dashboard port."
  type        = number
  default     = 8088
}

# --- Placeholders: wire these to your provider's resources -------------------
#
# 1. Secret       — store var.api_token in your secret manager.
# 2. Storage      — a persistent volume / disk for the config store + history.
# 3. Compute      — ECS/Fargate task, GCE, or a K8s workload running:
#                     vecshield-platform serve --config /data/vecshield.json
#                       --host 0.0.0.0 --port ${var.port}
# 4. Network      — private subnet + internal load balancer; do NOT expose the
#                   API publicly without your own authN/Z + TLS in front.
# 5. Scheduler    — a scheduled task running `schedule --once` for audits.
#
# Example (pseudo):
# resource "aws_secretsmanager_secret_version" "token" { ... }
# resource "aws_ecs_task_definition" "vecshield" { ... }
# resource "aws_ecs_service" "vecshield" { ... }

output "next_steps" {
  value = "Replace the placeholder resources with your cloud provider's compute, secret, storage, and networking resources."
}
