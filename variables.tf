variable "acme_server_url" {
  description = "acme server url to use"
  type        = string
}

variable "region" {
  description = "AWS region to deploy resources in"
  type        = string
}

variable "email" {
  description = "email for TFE admin"
  type        = string
}

variable "tfe_license" {
  description = "TFE license"
  type        = string
  sensitive   = true
}

variable "tfe_admin_password" {
  description = "TFE admin password"
  type        = string
  sensitive   = true
}

variable "tfe_encryption_password" {
  description = "TFE encryption password"
  type        = string
  sensitive   = true
}

variable "tfe_image_tag" {
  description = "TFE docker image tag to use"
  type        = string
  default     = "latest"
}

variable "dns_record" {
  description = "DNS record for TFE instance"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"
}

variable "name" {
  description = "Name prefix for resources"
  type        = string
  default     = "tfe-instance"
}

variable "hosted_zone_name" {
  description = "Route53 Hosted Zone Name"
  type        = string
}

variable "certs_dir" {
  description = "Directory to store TLS certificates"
  type        = string
  default     = "/etc/terraform-enterprise/certs"
}

variable "data_dir" {
  description = "Directory to store TFE data"
  type        = string
  default     = "/opt/terraform-enterprise/data"
}

variable "ssm_tls_cert" {
  description = "SSM Parameter Store name for TLS certificate"
  type        = string
  default     = "/tfe/server/cert1"
}

variable "ssm_tls_key" {
  description = "SSM Parameter Store name for TLS private key"
  type        = string
  default     = "/tfe/server/key1"
}

variable "ssm_tls_bundle" {
  description = "SSM Parameter Store name for TLS bundle cert"
  type        = string
  default     = "/tfe/server/bundle1"
}

variable "s3_bucket_name" {
  description = "S3 bucket name for TFE data storage"
  type        = string
}

variable "rds_password" {
  description = "RDS master user password"
  type        = string
  sensitive   = true
}

variable "db_user" {
  description = "RDS user"
  type        = string
}

variable "rds_db_name" {
  description = "RDS database name"
  type        = string
}

variable "alb_name" {
  description = "Load Balancer name"
  type        = string
}

variable "server_port" {
  description = "Port for the LB"
  type        = number
  default     = 443
}

variable "server_protocol" {
  description = "Protocol for the LB"
  type        = string
  default     = "HTTPS"
}

variable "redis_name" {
  description = "Name for the Redis cluster"
  type        = string
}