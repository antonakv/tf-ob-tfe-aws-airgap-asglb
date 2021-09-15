# tf-ob-tfe-aws-airgap pre-req

This manual is dedicated to upload Terrafrom Enterprise assets required for the installation to Amazon S3

## Requirements

- Hashicorp terraform recent version installed
[Terraform installation manual](https://learn.hashicorp.com/tutorials/terraform/install-cli)

- git installed
[Git installation manual](https://git-scm.com/download/mac)

- Amazon AWS account credentials saved in .aws/credentials file
[Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

## Preparation 

- Create file testing.tfvars with following contents

```
region        = "eu-central-1"
```

- Create folder `upload`

```bash
mkdir upload
```

- Copy to folder `upload` following files

  - latest.tar.gz

  - license.rli

  - tfe-557.airgap

## Run terraform code

- Initialize terraform

```bash
terraform init
```

Sample result

```
Initializing the backend...

Initializing provider plugins...
- Reusing previous version of hashicorp/aws from the dependency lock file
- Using previously-installed hashicorp/aws v3.57.0

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
```

- Run the `terraform apply` to upload the assets to the Amazon S3 bucket

```bash
terraform apply
```

Sample result

```
$ terraform apply  

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_iam_instance_profile.aakulov-aws4-iam-role-airgap will be created
  + resource "aws_iam_instance_profile" "aakulov-aws4-iam-role-airgap" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = "aakulov-aws4-iam-role-airgap"
      + path        = "/"
      + role        = "aakulov-aws4-iam-role-ec2-s3-airgap"
      + tags_all    = (known after apply)
      + unique_id   = (known after apply)
    }

  # aws_iam_role.aakulov-aws4-iam-role-airgap will be created
  + resource "aws_iam_role" "aakulov-aws4-iam-role-airgap" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                      + Sid       = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "aakulov-aws4-iam-role-ec2-s3-airgap"
      + path                  = "/"
      + tags                  = {
          + "tag-key" = "aakulov-aws4-iam-role-airgap"
        }
      + tags_all              = {
          + "tag-key" = "aakulov-aws4-iam-role-airgap"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # aws_iam_role_policy.aakulov-aws4-iam-role-airgap will be created
  + resource "aws_iam_role_policy" "aakulov-aws4-iam-role-airgap" {
      + id     = (known after apply)
      + name   = "aakulov-aws4-iam-role-airgap"
      + policy = (known after apply)
      + role   = (known after apply)
    }

  # aws_s3_bucket.aws4-airgap will be created
  + resource "aws_s3_bucket" "aws4-airgap" {
      + acceleration_status         = (known after apply)
      + acl                         = "private"
      + arn                         = (known after apply)
      + bucket                      = "aakulov-aws4-tfe-airgap"
      + bucket_domain_name          = (known after apply)
      + bucket_regional_domain_name = (known after apply)
      + force_destroy               = true
      + hosted_zone_id              = (known after apply)
      + id                          = (known after apply)
      + region                      = (known after apply)
      + request_payer               = (known after apply)
      + tags                        = {
          + "Name" = "aakulov-aws4-tfe-airgap"
        }
      + tags_all                    = {
          + "Name" = "aakulov-aws4-tfe-airgap"
        }
      + website_domain              = (known after apply)
      + website_endpoint            = (known after apply)

      + versioning {
          + enabled    = (known after apply)
          + mfa_delete = (known after apply)
        }
    }

  # aws_s3_bucket_object.upload1 will be created
  + resource "aws_s3_bucket_object" "upload1" {
      + acl                    = "private"
      + bucket                 = (known after apply)
      + bucket_key_enabled     = (known after apply)
      + content_type           = (known after apply)
      + etag                   = "2d29bad3e2555b62809960d052f55d87"
      + force_destroy          = false
      + id                     = (known after apply)
      + key                    = "latest.tar.gz"
      + kms_key_id             = (known after apply)
      + server_side_encryption = (known after apply)
      + source                 = "upload/latest.tar.gz"
      + storage_class          = (known after apply)
      + tags_all               = (known after apply)
      + version_id             = (known after apply)
    }

  # aws_s3_bucket_object.upload4 will be created
  + resource "aws_s3_bucket_object" "upload4" {
      + acl                    = "private"
      + bucket                 = (known after apply)
      + bucket_key_enabled     = (known after apply)
      + content_type           = (known after apply)
      + etag                   = "85d44faf2d64adb00d051feb4691bd95"
      + force_destroy          = false
      + id                     = (known after apply)
      + key                    = "license.rli"
      + kms_key_id             = (known after apply)
      + server_side_encryption = (known after apply)
      + source                 = "upload/license.rli"
      + storage_class          = (known after apply)
      + tags_all               = (known after apply)
      + version_id             = (known after apply)
    }

  # aws_s3_bucket_object.upload5 will be created
  + resource "aws_s3_bucket_object" "upload5" {
      + acl                    = "private"
      + bucket                 = (known after apply)
      + bucket_key_enabled     = (known after apply)
      + content_type           = (known after apply)
      + etag                   = "82686b24f1dd53c73bd430ebeebdfa75"
      + force_destroy          = false
      + id                     = (known after apply)
      + key                    = "tfe-557.airgap"
      + kms_key_id             = (known after apply)
      + server_side_encryption = (known after apply)
      + source                 = "upload/tfe-557.airgap"
      + storage_class          = (known after apply)
      + tags_all               = (known after apply)
      + version_id             = (known after apply)
    }

  # aws_s3_bucket_public_access_block.aakulov-aws4-iam-role-airgap will be created
  + resource "aws_s3_bucket_public_access_block" "aakulov-aws4-iam-role-airgap" {
      + block_public_acls       = true
      + block_public_policy     = true
      + bucket                  = (known after apply)
      + id                      = (known after apply)
      + ignore_public_acls      = true
      + restrict_public_buckets = true
    }

Plan: 8 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + s3_bucket_for_tf-ob-tfe-aws-airgap = (known after apply)

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

aws_iam_role.aakulov-aws4-iam-role-airgap: Creating...
aws_s3_bucket.aws4-airgap: Creating...
aws_iam_role.aakulov-aws4-iam-role-airgap: Creation complete after 2s [id=aakulov-aws4-iam-role-ec2-s3-airgap]
aws_iam_instance_profile.aakulov-aws4-iam-role-airgap: Creating...
aws_iam_instance_profile.aakulov-aws4-iam-role-airgap: Creation complete after 1s [id=aakulov-aws4-iam-role-airgap]
aws_s3_bucket.aws4-airgap: Creation complete after 4s [id=aakulov-aws4-tfe-airgap]
aws_s3_bucket_public_access_block.aakulov-aws4-iam-role-airgap: Creating...
aws_iam_role_policy.aakulov-aws4-iam-role-airgap: Creating...
aws_s3_bucket_object.upload4: Creating...
aws_s3_bucket_object.upload4: Creation complete after 0s [id=license.rli]
aws_s3_bucket_public_access_block.aakulov-aws4-iam-role-airgap: Creation complete after 0s [id=aakulov-aws4-tfe-airgap]
aws_iam_role_policy.aakulov-aws4-iam-role-airgap: Creation complete after 1s [id=aakulov-aws4-iam-role-ec2-s3-airgap:aakulov-aws4-iam-role-airgap]
aws_s3_bucket_object.upload1: Creating...
aws_s3_bucket_object.upload5: Creating...
aws_s3_bucket_object.upload1: Still creating... [10s elapsed]

[ Removed part of the output]

aws_s3_bucket_object.upload5: Still creating... [41m20s elapsed]
aws_s3_bucket_object.upload5: Still creating... [41m30s elapsed]
aws_s3_bucket_object.upload5: Still creating... [41m40s elapsed]
aws_s3_bucket_object.upload5: Still creating... [41m50s elapsed]
aws_s3_bucket_object.upload5: Still creating... [42m0s elapsed]
aws_s3_bucket_object.upload5: Creation complete after 42m5s [id=tfe-557.airgap]

Apply complete! Resources: 8 added, 0 changed, 0 destroyed.

Outputs:

s3_bucket_for_tf-ob-tfe-aws-airgap = "arn:aws:s3:::aakulov-aws4-tfe-airgap"
```

