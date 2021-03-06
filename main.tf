provider "aws" {
  region = var.region
}

resource "tls_private_key" "aws5" {
  algorithm = "RSA"
}

resource "tls_self_signed_cert" "aws5" {
  key_algorithm         = tls_private_key.aws5.algorithm
  private_key_pem       = tls_private_key.aws5.private_key_pem
  validity_period_hours = 8928
  early_renewal_hours   = 744

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]

  dns_names = [var.tfe_hostname]

  subject {
    common_name  = var.tfe_hostname
    organization = "aakulov sandbox"
  }
}

resource "aws_vpc" "vpc" {
  cidr_block           = var.cidr_vpc
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "aakulov-aws5"
  }
}

resource "aws_subnet" "subnet_private1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet1
  availability_zone = "eu-central-1b"
  tags = {
    Name = "aakulov-aws5-private-1"
  }
}

resource "aws_subnet" "subnet_private2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet3
  availability_zone = "eu-central-1c"
  tags = {
    Name = "aakulov-aws5-private-2"
  }
}

resource "aws_subnet" "subnet_public1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet2
  availability_zone = "eu-central-1b"
  tags = {
    Name = "aakulov-aws5-public-1"
  }
}

resource "aws_subnet" "subnet_public2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet4
  availability_zone = "eu-central-1c"
  tags = {
    Name = "aakulov-aws5-public-2"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "aakulov-aws5"
  }
}

resource "aws_eip" "eip1" {
  vpc = true
  tags = {
    Name = "aakulov-aws5-1"
  }
}

resource "aws_eip" "eip2" {
  vpc = true
  tags = {
    Name = "aakulov-aws5-2"
  }
}

resource "aws_nat_gateway" "nat1" {
  allocation_id = aws_eip.eip1.id
  subnet_id     = aws_subnet.subnet_public1.id
  depends_on    = [aws_internet_gateway.igw]
  tags = {
    Name = "aakulov-aws5-1"
  }
}

resource "aws_nat_gateway" "nat2" {
  allocation_id = aws_eip.eip2.id
  subnet_id     = aws_subnet.subnet_public2.id
  depends_on    = [aws_internet_gateway.igw]
  tags = {
    Name = "aakulov-aws5-2"
  }
}

resource "aws_route_table" "aws5-private-1" {
  vpc_id = aws_vpc.vpc.id


  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat1.id
  }

  tags = {
    Name = "aakulov-aws5-private-1"
  }
}

resource "aws_route_table" "aws5-private-2" {
  vpc_id = aws_vpc.vpc.id


  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat2.id
  }

  tags = {
    Name = "aakulov-aws5-private-2"
  }
}

resource "aws_route_table" "aws5-public-1" {
  vpc_id = aws_vpc.vpc.id


  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "aakulov-aws5-public-1"
  }
}

resource "aws_route_table" "aws5-public-2" {
  vpc_id = aws_vpc.vpc.id


  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "aakulov-aws5-public-2"
  }
}

resource "aws_route_table_association" "aws5-private-1" {
  subnet_id      = aws_subnet.subnet_private1.id
  route_table_id = aws_route_table.aws5-private-1.id
}

resource "aws_route_table_association" "aws5-private-2" {
  subnet_id      = aws_subnet.subnet_private2.id
  route_table_id = aws_route_table.aws5-private-2.id
}

resource "aws_route_table_association" "aws5-public-1" {
  subnet_id      = aws_subnet.subnet_public1.id
  route_table_id = aws_route_table.aws5-public-1.id
}

resource "aws_route_table_association" "aws5-public-2" {
  subnet_id      = aws_subnet.subnet_public2.id
  route_table_id = aws_route_table.aws5-public-2.id
}

resource "aws_security_group" "aws5-internal-sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "aakulov-aws5-internal-sg"
  tags = {
    Name = "aakulov-aws5-internal-sg"
  }

  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.aws5-lb-sg.id]
  }

  ingress {
    from_port   = 8800
    to_port     = 8800
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 8800
    to_port         = 8800
    protocol        = "tcp"
    security_groups = [aws_security_group.aws5-lb-sg.id]
  }

  ingress {
    from_port = 5432
    to_port   = 5432
    protocol  = "tcp"
    self      = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "aws5-public-sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "aakulov-aws5-public-sg"
  tags = {
    Name = "aakulov-aws5-public-sg"
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8800
    to_port     = 8800
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
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

resource "aws_route53_record" "aws5" {
  zone_id         = "Z077919913NMEBCGB4WS0"
  name            = var.tfe_hostname
  type            = "CNAME"
  ttl             = "300"
  records         = [aws_lb.aws5.dns_name]
  allow_overwrite = true
}

resource "aws_acm_certificate" "aws5" {
  domain_name       = var.tfe_hostname
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_acm_certificate_validation" "aws5" {
  certificate_arn = aws_acm_certificate.aws5.arn
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_target_group" "aws5-443" {
  name        = "aakulov-aws5-443"
  port        = 443
  protocol    = "HTTPS"
  vpc_id      = aws_vpc.vpc.id
  target_type = "instance"
  slow_start  = 400
  lifecycle {
    create_before_destroy = true
  }
  stickiness {
    enabled = true
    type    = "lb_cookie"
  }
}

resource "aws_lb_target_group" "aws5-8800" {
  name        = "aakulov-aws5-8800"
  port        = 8800
  protocol    = "HTTPS"
  vpc_id      = aws_vpc.vpc.id
  target_type = "instance"
  slow_start  = 400
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "aws5-lb-sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "aakulov-aws5-lb-sg"
  tags = {
    Name = "aakulov-aws5-lb-sg"
  }

  ingress {
    from_port   = 8800
    to_port     = 8800
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Extra security group rules to avoid Cycle error

resource "aws_security_group_rule" "aws5-lb-sg-to-aws5-internal-sg-allow-443" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.aws5-internal-sg.id
  security_group_id        = aws_security_group.aws5-lb-sg.id
}

resource "aws_security_group_rule" "aws5-lb-sg-to-aws5-internal-sg-allow-8800" {
  type                     = "egress"
  from_port                = 8800
  to_port                  = 8800
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.aws5-internal-sg.id
  security_group_id        = aws_security_group.aws5-lb-sg.id
}

resource "aws_lb" "aws5" {
  name                             = "aakulov-aws5"
  internal                         = false
  load_balancer_type               = "application"
  security_groups                  = [aws_security_group.aws5-lb-sg.id]
  enable_cross_zone_load_balancing = true
  subnets                          = [aws_subnet.subnet_public1.id, aws_subnet.subnet_public2.id]
  enable_deletion_protection       = false
}

resource "aws_lb_listener" "aws5-443" {
  load_balancer_arn = aws_lb.aws5.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.aws5.arn
  ssl_policy        = "ELBSecurityPolicy-FS-1-2-Res-2020-10"
  depends_on = [
    aws_lb.aws5
  ]
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.aws5-443.arn
  }
}

resource "aws_lb_listener" "aws5-8800" {
  load_balancer_arn = aws_lb.aws5.arn
  port              = "8800"
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.aws5.arn
  ssl_policy        = "ELBSecurityPolicy-FS-1-2-Res-2020-10"
  depends_on = [
    aws_lb.aws5
  ]
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.aws5-8800.arn
  }
}

resource "aws_placement_group" "aws5" {
  name     = "aws5"
  strategy = "spread"
}

variable "aws_autoscaling_group_tags" {
  default = [
    {
      key                 = "Name"
      value               = "aakulov-aws5-asg#"
      propagate_at_launch = true
    },
  ]
}

resource "aws_autoscaling_group" "aws5" {
  name_prefix               = "aakulov-aws5-asg"
  launch_configuration      = aws_launch_configuration.aws5.name
  min_size                  = 1
  max_size                  = 2
  health_check_grace_period = 400
  force_delete              = true
  placement_group           = aws_placement_group.aws5.id
  vpc_zone_identifier       = [aws_subnet.subnet_private1.id, aws_subnet.subnet_private2.id]
  target_group_arns         = [aws_lb_target_group.aws5-443.arn, aws_lb_target_group.aws5-8800.arn]
  timeouts {
    delete = "15m"
  }
  lifecycle {
    create_before_destroy = true
  }
  warm_pool {
    pool_state                  = "Running"
    min_size                    = 1
    max_group_prepared_capacity = 1
  }
  depends_on = [aws_lb.aws5]
  tags       = var.aws_autoscaling_group_tags
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.aws5.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }
  zone_id         = "Z077919913NMEBCGB4WS0"
  ttl             = 60
  type            = each.value.type
  name            = each.value.name
  records         = [each.value.record]
  allow_overwrite = true
}

resource "aws_db_subnet_group" "aws5" {
  name       = "aakulov-aws5"
  subnet_ids = [aws_subnet.subnet_private1.id, aws_subnet.subnet_private2.id]
  tags = {
    Name = "aakulov-aws5"
  }
}

resource "aws_db_instance" "aws5" {
  allocated_storage      = 20
  max_allocated_storage  = 100
  engine                 = "postgres"
  engine_version         = "12.7"
  name                   = "mydbtfe"
  username               = "postgres"
  password               = var.db_password
  instance_class         = var.db_instance_type
  db_subnet_group_name   = aws_db_subnet_group.aws5.name
  vpc_security_group_ids = [aws_security_group.aws5-internal-sg.id]
  skip_final_snapshot    = true
  tags = {
    Name = "aakulov-aws5"
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "aakulov-aws5-tfe-data"
  acl    = "private"
  versioning {
    enabled = true
  }
  force_destroy = false
  tags = {
    Name = "aakulov-aws5-tfe-data"
  }
  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "aakulov-aws5-tfe-logs"
  acl    = "private"
  versioning {
    enabled = true
  }
  force_destroy = true
  tags = {
    Name = "aakulov-aws5-tfe-logs"
  }
  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

resource "aws_iam_role" "aakulov-aws5-iam-role-ec2-s3" {
  name = "aakulov-aws5-iam-role-ec2-s3"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    tag-key = "aakulov-aws5-iam-role-ec2-s3"
  }
}

resource "aws_iam_instance_profile" "aakulov-aws5-ec2-s3" {
  name = "aakulov-aws5-ec2-s3"
  role = aws_iam_role.aakulov-aws5-iam-role-ec2-s3.name
}

resource "aws_iam_role_policy" "aakulov-aws5-ec2-s3" {
  name = "aakulov-aws5-ec2-s3"
  role = aws_iam_role.aakulov-aws5-iam-role-ec2-s3.id
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "VisualEditor0",
        "Effect" : "Allow",
        "Action" : [
          "s3:ListStorageLensConfigurations",
          "s3:ListAccessPointsForObjectLambda",
          "s3:GetAccessPoint",
          "s3:PutAccountPublicAccessBlock",
          "s3:GetAccountPublicAccessBlock",
          "s3:ListAllMyBuckets",
          "s3:ListAccessPoints",
          "s3:ListJobs",
          "s3:PutStorageLensConfiguration",
          "s3:CreateJob",
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "VisualEditor1",
        "Effect" : "Allow",
        "Action" : "s3:*",
        "Resource" : aws_s3_bucket.data.arn
      }
    ]
  })
}

data "template_file" "install_tfe_sh" {
  template = file("templates/install_tfe.sh.tpl")
  vars = {
    enc_password  = var.enc_password
    hostname      = var.tfe_hostname
    pgsqlhostname = aws_db_instance.aws5.address
    pgsqlpassword = var.db_password
    pguser        = aws_db_instance.aws5.username
    s3bucket      = aws_s3_bucket.data.bucket
    s3region      = var.region
    cert_pem      = tls_self_signed_cert.aws5.cert_pem
    key_pem       = tls_private_key.aws5.private_key_pem
  }
}

data "template_cloudinit_config" "aws5_cloudinit" {
  gzip          = true
  base64_encode = true

  part {
    filename     = "install_tfe.sh"
    content_type = "text/x-shellscript"
    content      = data.template_file.install_tfe_sh.rendered
  }
}

resource "aws_launch_configuration" "aws5" {
  name_prefix          = "aakulov-aws5-asg"
  image_id             = var.ami
  instance_type        = var.instance_type
  key_name             = var.key_name
  security_groups      = [aws_security_group.aws5-internal-sg.id]
  user_data            = data.template_cloudinit_config.aws5_cloudinit.rendered
  iam_instance_profile = aws_iam_instance_profile.aakulov-aws5-ec2-s3.id
}

data "aws_caller_identity" "current" {}

output "aws_url" {
  value       = aws_route53_record.aws5.name
  description = "Domain name of load balancer"
}
