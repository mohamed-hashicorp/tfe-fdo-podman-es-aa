terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    acme = {
      source  = "vancluever/acme"
      version = "~> 2.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.region
}

provider "acme" {
  server_url = var.acme_server_url
}

# --- Data Sources to capture the latest Ubuntu AMI ---
data "aws_ami" "ubuntu_noble" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_route53_zone" "server_zone" {
  name         = var.hosted_zone_name
  private_zone = false
}

data "aws_caller_identity" "current" {}

# --- IAM Role for SSM ---
resource "aws_iam_role" "ssm" {
  name = "${var.name}-ssm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm" {
  name = "${var.name}-instance-profile"
  role = aws_iam_role.ssm.name
}

# --- Security Group ---
resource "aws_security_group" "web" {
  name        = "${var.name}-sg"
  description = "Allow HTTP, HTTPS and PostgreSQL only"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Vault"
    from_port   = 8201
    to_port     = 8201
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "PostgreSQL"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- Application Load Balancer ---
resource "aws_lb" "example" {
  name               = var.alb_name
  load_balancer_type = "application"
  subnets            = data.aws_subnets.default.ids
  security_groups    = [aws_security_group.web.id]
}

# --- CNAME record to ALB FQDN ---
# NOTE: This MUST NOT be the hosted zone apex.
resource "aws_route53_record" "server" {
  zone_id = data.aws_route53_zone.server_zone.zone_id
  name    = var.dns_record
  type    = "CNAME"
  ttl     = 300
  records = [aws_lb.example.dns_name]
}

# --- Target Group ---
resource "aws_lb_target_group" "asg" {
  name     = var.alb_name
  port     = var.server_port
  protocol = var.server_protocol
  vpc_id   = data.aws_vpc.default.id

  health_check {
    path                = "/_health_check"
    protocol            = var.server_protocol
    matcher             = "200-399"
    interval            = 15
    timeout             = 3
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

# --- ACM Certificate for Load Balancer (DNS validated in Route53) ---
resource "aws_acm_certificate" "alb" {
  domain_name       = var.dns_record
  validation_method = "DNS"
}

resource "aws_route53_record" "alb_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.alb.domain_validation_options : dvo.domain_name => {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  }

  zone_id = data.aws_route53_zone.server_zone.zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60
  records = [each.value.value]
}

resource "aws_acm_certificate_validation" "alb" {
  certificate_arn         = aws_acm_certificate.alb.arn
  validation_record_fqdns = [for r in aws_route53_record.alb_cert_validation : r.fqdn]
}

# --- Load balancer Listener (HTTPS) ---
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  certificate_arn = aws_acm_certificate_validation.alb.certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "404: page not found"
      status_code  = 404
    }
  }
}

# --- Listener Rule to forward traffic to ASG Target Group ---
resource "aws_lb_listener_rule" "asg" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 100

  condition {
    path_pattern {
      values = ["/*"]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.asg.arn
  }
}

# --- ACME account private key (Let's Encrypt account) ---
resource "tls_private_key" "acme_account" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "acme_registration" "this" {
  account_key_pem = tls_private_key.acme_account.private_key_pem
  email_address   = var.email
}

# --- ACME certificate (for instance/app usage; ALB uses ACM above) ---
resource "acme_certificate" "server" {
  account_key_pem    = acme_registration.this.account_key_pem
  common_name        = var.dns_record
  min_days_remaining = 30

  dns_challenge {
    provider = "route53"
    config = {
      AWS_HOSTED_ZONE_ID = data.aws_route53_zone.server_zone.zone_id
      AWS_REGION         = var.region
    }
  }
}

#Store cert and key in SSM Parameter Store
resource "aws_ssm_parameter" "tls_cert" {
  name  = var.ssm_tls_cert
  type  = "SecureString"
  value = acme_certificate.server.certificate_pem
}

resource "aws_ssm_parameter" "tls_key" {
  name  = var.ssm_tls_key
  type  = "SecureString"
  value = acme_certificate.server.private_key_pem
}

resource "aws_ssm_parameter" "tls_bundle" {
  name  = var.ssm_tls_bundle
  type  = "SecureString"
  value = acme_certificate.server.issuer_pem
}


# IAM Policy to allow EC2 instance to read the exact SSM parameters
resource "aws_iam_role_policy" "ssm_tls_access" {
  role = aws_iam_role.ssm.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = [
        "ssm:GetParameter",
        "ssm:GetParameters",
      ],
      Resource = [
        "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter${var.ssm_tls_cert}",
        "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter${var.ssm_tls_key}",
        "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter${var.ssm_tls_bundle}",
      ]
    }]
  })
}

# --- Launch Configuration ---
resource "aws_launch_configuration" "example" {
  name_prefix                 = "${var.name}-lc-"
  image_id                    = data.aws_ami.ubuntu_noble.id
  instance_type               = var.instance_type
  security_groups             = [aws_security_group.web.id]
  iam_instance_profile        = aws_iam_instance_profile.ssm.name
  associate_public_ip_address = true

  root_block_device {
    volume_size = 100
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = base64gzip(templatefile("${path.module}/cloud-init.tftpl", {
    server_cert             = var.ssm_tls_cert
    private_key             = var.ssm_tls_key
    bundle_certs            = var.ssm_tls_bundle
    tfe_license             = var.tfe_license
    tfe_hostname            = var.dns_record
    tfe_admin_password      = var.tfe_admin_password
    tfe_encryption_password = var.tfe_encryption_password
    tfe_image_tag           = var.tfe_image_tag

    certs_dir = var.certs_dir
    data_dir  = var.data_dir

    s3_bucket_name = var.s3_bucket_name
    rds_password   = var.rds_password
    db_user        = var.db_user
    db_endpoint    = local.rds_endpoint
    rds_db_name    = var.rds_db_name
    region         = var.region

    # PRIVATE_IP = "$${PRIVATE_IP}"
  }))

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_ssm_parameter.tls_cert,
    aws_ssm_parameter.tls_key,
    aws_ssm_parameter.tls_bundle
  ]
}

# --- Auto Scaling Group ---
resource "aws_autoscaling_group" "example" {
  launch_configuration = aws_launch_configuration.example.name
  vpc_zone_identifier  = data.aws_subnets.default.ids

  target_group_arns = [aws_lb_target_group.asg.arn]
  health_check_type = "ELB"
  health_check_grace_period = 900  
  min_size          = 2
  max_size          = 3

  tag {
    key                 = "Name"
    value               = "terraform-asg-example"
    propagate_at_launch = true
  }
}

# --- S3 Bucket ---
resource "aws_s3_bucket" "example" {
  bucket = var.s3_bucket_name
  tags   = { Name = var.s3_bucket_name }
}

resource "aws_iam_role_policy" "s3-access-policy" {
  name = "${var.s3_bucket_name}-policy"
  role = aws_iam_role.ssm.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid    = "BucketAccess",
      Effect = "Allow",
      Action = [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:DeleteObject",
        "s3:GetBucketLocation",
      ],
      Resource = [
        aws_s3_bucket.example.arn,
        "${aws_s3_bucket.example.arn}/*",
      ]
    }]
  })
}

# --- RDS Instance ---
resource "aws_db_subnet_group" "default" {
  name       = "${var.name}-db-subnet-group"
  subnet_ids = data.aws_subnets.default.ids
  tags       = { Name = "${var.name}-db-subnet-group" }
}

resource "aws_db_instance" "default" {
  allocated_storage    = 10
  engine               = "postgres"
  engine_version       = "14.18"
  instance_class       = "db.t3.large"
  username             = var.db_user
  password             = var.rds_password
  db_name              = var.rds_db_name
  parameter_group_name = "default.postgres14"

  skip_final_snapshot = true
  publicly_accessible = false

  vpc_security_group_ids = [aws_security_group.web.id]
  db_subnet_group_name   = aws_db_subnet_group.default.name

  identifier                  = "${var.name}-rds"
  allow_major_version_upgrade = true

  tags = { Name = "${var.name}-rds" }
}

locals {
  server_fullchain_pem = "${acme_certificate.server.certificate_pem}\n${acme_certificate.server.issuer_pem}"
  rds_endpoint         = "${aws_db_instance.default.address}:${aws_db_instance.default.port}"
}
