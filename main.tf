provider "aws" {
  region = var.region
}

resource "tls_private_key" "aws4" {
  algorithm = "RSA"
}

resource "tls_self_signed_cert" "aws4" {
  key_algorithm         = tls_private_key.aws4.algorithm
  private_key_pem       = tls_private_key.aws4.private_key_pem
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
    Name = "aakulov-aws4"
  }
}

resource "aws_subnet" "subnet_private1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet1
  availability_zone = "eu-central-1b"
}

resource "aws_subnet" "subnet_private2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet3
  availability_zone = "eu-central-1c"
}

resource "aws_subnet" "subnet_public1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet2
  availability_zone = "eu-central-1b"
}

resource "aws_subnet" "subnet_public2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet4
  availability_zone = "eu-central-1c"
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "aakulov-aws4"
  }
}

resource "aws_eip" "aws4" {
  vpc = true
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.aws4.id
  subnet_id     = aws_subnet.subnet_public1.id
  depends_on    = [aws_internet_gateway.igw]
  tags = {
    Name = "aakulov-aws4"
  }
}

resource "aws_route_table" "aws4-private" {
  vpc_id = aws_vpc.vpc.id


  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "aakulov-aws4-private"
  }
}

resource "aws_route_table" "aws4-public" {
  vpc_id = aws_vpc.vpc.id


  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "aakulov-aws4-public"
  }
}

resource "aws_route_table_association" "aws4-private" {
  subnet_id      = aws_subnet.subnet_private1.id
  route_table_id = aws_route_table.aws4-private.id
}

resource "aws_route_table_association" "aws4-public" {
  subnet_id      = aws_subnet.subnet_public1.id
  route_table_id = aws_route_table.aws4-public.id
}

resource "aws_security_group" "aws4-internal-sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "aakulov-aws4-internal-sg"
  tags = {
    Name = "aakulov-aws4-internal-sg"
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
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.aakulov-aws4.id]
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

resource "aws_security_group" "aakulov-aws4" {
  vpc_id = aws_vpc.vpc.id
  name   = "aakulov-aws4-sg"
  tags = {
    Name = "aakulov-aws4-sg"
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

resource "aws_route53_record" "aws4" {
  zone_id         = "Z077919913NMEBCGB4WS0"
  name            = var.tfe_hostname
  type            = "A"
  ttl             = "300"
  records         = [aws_instance.aws4.public_ip]
  allow_overwrite = true
}

resource "aws_db_subnet_group" "aws4" {
  name       = "aakulov-aws4"
  subnet_ids = [aws_subnet.subnet_public1.id, aws_subnet.subnet_public2.id, aws_subnet.subnet_private1.id, aws_subnet.subnet_private2.id]
  tags = {
    Name = "aakulov-aws4"
  }
}

resource "aws_db_instance" "aws4" {
  allocated_storage      = 20
  max_allocated_storage  = 100
  engine                 = "postgres"
  engine_version         = "12.7"
  name                   = "mydbtfe"
  username               = "postgres"
  password               = var.db_password
  instance_class         = "db.t2.micro"
  db_subnet_group_name   = aws_db_subnet_group.aws4.name
  vpc_security_group_ids = [aws_security_group.aakulov-aws4.id]
  skip_final_snapshot    = true
  tags = {
    Name = "aakulov-aws4"
  }
}

resource "aws_s3_bucket" "aws4" {
  bucket        = "aakulov-aws4-tfe-data"
  acl           = "private"
  force_destroy = true
  tags = {
    Name = "aakulov-aws4-tfe-data"
  }
}

resource "aws_s3_bucket_public_access_block" "aws4" {
  bucket = aws_s3_bucket.aws4.id

  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

resource "aws_iam_role" "aakulov-aws4-iam-role-ec2-s3" {
  name = "aakulov-aws4-iam-role-ec2-s3"
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
    tag-key = "aakulov-aws4-iam-role-ec2-s3"
  }
}

resource "aws_iam_instance_profile" "aakulov-aws4-ec2-s3" {
  name = "aakulov-aws4-ec2-s3"
  role = aws_iam_role.aakulov-aws4-iam-role-ec2-s3.name
}

resource "aws_iam_role_policy" "aakulov-aws4-ec2-s3" {
  name = "aakulov-aws4-ec2-s3"
  role = aws_iam_role.aakulov-aws4-iam-role-ec2-s3.id
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
        "Resource" : aws_s3_bucket.aws4.arn
      }
    ]
  })
}

data "template_file" "install_tfe_sh" {
  template = file("templates/install_tfe.sh.tpl")
  vars = {
    enc_password  = var.enc_password
    hostname      = var.tfe_hostname
    pgsqlhostname = aws_db_instance.aws4.address
    pgsqlpassword = var.db_password
    pguser        = aws_db_instance.aws4.username
    s3bucket      = aws_s3_bucket.aws4.bucket
    s3region      = var.region
    cert_pem      = tls_self_signed_cert.aws4.cert_pem
    key_pem       = tls_private_key.aws4.private_key_pem
  }
}

data "template_cloudinit_config" "aws4_cloudinit" {
  gzip          = true
  base64_encode = true

  part {
    filename     = "install_tfe.sh"
    content_type = "text/x-shellscript"
    content      = data.template_file.install_tfe_sh.rendered
  }
}

resource "aws_instance" "aws4" {
  ami                         = var.ami
  instance_type               = var.instance_type
  key_name                    = var.key_name
  vpc_security_group_ids      = [aws_security_group.aakulov-aws4.id]
  subnet_id                   = aws_subnet.subnet_public1.id
  associate_public_ip_address = true
  user_data                   = data.template_cloudinit_config.aws4_cloudinit.rendered
  iam_instance_profile        = aws_iam_instance_profile.aakulov-aws4-ec2-s3.id
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
  tags = {
    Name = "aakulov-aws4"
  }
}

output "aws_url" {
  value = aws_route53_record.aws4.name
}
