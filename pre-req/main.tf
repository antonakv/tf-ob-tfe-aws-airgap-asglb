provider "aws" {
  region = var.region
}

resource "aws_s3_bucket" "aws4-airgap" {
  bucket = "aakulov-aws4-tfe-airgap"
  acl    = "private"
  force_destroy = true
  tags = {
    Name = "aakulov-aws4-tfe-airgap"
  }
}

resource "aws_iam_role" "aakulov-aws4-iam-role-airgap" {
  name = "aakulov-aws4-iam-role-ec2-s3-airgap"
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
    tag-key = "aakulov-aws4-iam-role-airgap"
  }
}

resource "aws_iam_instance_profile" "aakulov-aws4-iam-role-airgap" {
  name = "aakulov-aws4-iam-role-airgap"
  role = aws_iam_role.aakulov-aws4-iam-role-airgap.name
}

resource "aws_iam_role_policy" "aakulov-aws4-iam-role-airgap" {
  name = "aakulov-aws4-iam-role-airgap"
  role = aws_iam_role.aakulov-aws4-iam-role-airgap.id
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
          "s3:CreateJob"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "VisualEditor1",
        "Effect" : "Allow",
        "Action" : "s3:*",
        "Resource" : aws_s3_bucket.aws4-airgap.arn
      }
    ]
  })
}

resource "aws_s3_bucket_public_access_block" "aakulov-aws4-iam-role-airgap" {
  bucket = aws_s3_bucket.aws4-airgap.id

  block_public_acls   = true
  block_public_policy = true
  restrict_public_buckets = true 
  ignore_public_acls = true
}

resource "aws_s3_bucket_object" "latest.tar.gz" {
  bucket = aws_s3_bucket.aws4-airgap.id
  key = "latest.tar.gz"
  source = "upload/latest.tar.gz"
  etag = filemd5("upload/latest.tar.gz")
}

resource "aws_s3_bucket_object" "license.rli" {
  bucket = aws_s3_bucket.aws4-airgap.id
  key = "license.rli"
  source = "upload/license.rli"
  etag = filemd5("upload/license.rli")
}

resource "aws_s3_bucket_object" "tfe-557.airgap" {
  bucket = aws_s3_bucket.aws4-airgap.id
  key = "tfe-557.airgap"
  source = "upload/tfe-557.airgap"
  etag = filemd5("upload/tfe-557.airgap")
}


output "s3_bucket_for_tf-ob-tfe-aws-airgap" {
  value = aws_s3_bucket.aws4-airgap.arn
}
