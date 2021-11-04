# tf-ob-tfe-aws-airgap-asglb

This manual is dedicated to Install Terraform Enterprise Prod version External Services ( S3 + DB ), ASG + LB with Valid Certificate AWS install with airgap

## Requirements

- Hashicorp terraform recent version installed
[Terraform installation manual](https://learn.hashicorp.com/tutorials/terraform/install-cli)

- git installed
[Git installation manual](https://git-scm.com/download/mac)

- Amazon AWS account credentials saved in `.aws/credentials` file
[Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

- Configured AWS Route53 DNS zone for domain `myname.hashicorp-success.com`
[Amazon Route53: Working with public hosted zones](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/AboutHZWorkingWith.html)

- Created Amazon EC2 key pair for Linux instance
[Create a key pair using Amazon EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair)

- Amazon AWS AMI image generated with Packer 
[Packer build of Ubuntu Focal AMI image](https://github.com/antonakv/packer-aws-ubuntufocal-tfe)

## Amazon AWS Resources diagram

 ![Diagram](https://github.com/antonakv/tf-ob-tfe-aws-airgap-asglb/raw/main/diagram/diagram.png)

## Preparation 

- Clone git repository

```bash
git clone https://github.com/antonakv/tf-ob-tfe-aws-airgap-asglb.git
```

Expected command output looks like this:

```bash
Cloning into 'tf-ob-tfe-aws-airgap-asglb'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 12 (delta 1), reused 3 (delta 0), pack-reused 0
Receiving objects: 100% (12/12), done.
Resolving deltas: 100% (1/1), done.
```

- Change folder to tf-ob-tfe-aws-airgap-asglb

```bash
cd tf-ob-tfe-aws-airgap-asglb
```

- Create file testing.tfvars with following contents

```
key_name         = "NameOfYourEC2Keypair"
ami              = "ami-0a3ca16f3cf729915" # Private AMI prepared for the TFE installation
instance_type    = "t3.large"
db_instance_type = "db.t3.medium"
region           = "eu-central-1"
cidr_vpc         = "10.5.0.0/16"
cidr_subnet1     = "10.5.1.0/24"
cidr_subnet2     = "10.5.2.0/24"
cidr_subnet3     = "10.5.3.0/24"
cidr_subnet4     = "10.5.4.0/24"
db_password      = "PutYourValueHere"
enc_password     = "PutYourValueHere"
tfe_hostname     = "tfe5.myname.hashicorp-success.com"
```

- Change folder to `pre-req`

- Follow `pre-req/README.md` manual to prepare assets on Amazon S3 required for the installation

- Change folder to Git repository root

`cd ..`

## Run terraform code

- In the same folder you were before, run 

```bash
terraform init
```

Sample result

```
$ terraform init   

Initializing the backend...

Initializing provider plugins...
- Reusing previous version of hashicorp/aws from the dependency lock file
- Reusing previous version of hashicorp/tls from the dependency lock file
- Reusing previous version of hashicorp/template from the dependency lock file
- Installing hashicorp/aws v3.52.0...
- Installed hashicorp/aws v3.52.0 (signed by HashiCorp)
- Installing hashicorp/tls v3.1.0...
- Installed hashicorp/tls v3.1.0 (signed by HashiCorp)
- Installing hashicorp/template v2.2.0...
- Installed hashicorp/template v2.2.0 (signed by HashiCorp)

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
```

- Run `terraform apply`

```
$ terraform apply

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
 <= read (data resources)

Terraform will perform the following actions:

  # data.template_cloudinit_config.aws5_cloudinit will be read during apply
  # (config refers to values not yet known)
 <= data "template_cloudinit_config" "aws5_cloudinit"  {
      + base64_encode = true
      + gzip          = true
      + id            = (known after apply)
      + rendered      = (known after apply)

      + part {
          + content      = (known after apply)
          + content_type = "text/x-shellscript"
          + filename     = "install_tfe.sh"
        }
    }

  # data.template_file.install_tfe_sh will be read during apply
  # (config refers to values not yet known)
 <= data "template_file" "install_tfe_sh"  {
      + id       = (known after apply)
      + rendered = (known after apply)
      + template = <<-EOT
            #!/usr/bin/env bash
            mkdir -p /home/ubuntu/install
            date >> /home/ubuntu/install/install_tfe.log
            
            EC2_INSTANCE_ID=$(ec2metadata --instance-id)
            
            echo "
            {
                \"aws_access_key_id\": {},
                \"aws_instance_profile\": {
                    \"value\": \"1\"
                },
                \"aws_secret_access_key\": {},
                \"azure_account_key\": {},
                \"azure_account_name\": {},
                \"azure_container\": {},
                \"azure_endpoint\": {},
                \"backup_token\": {
                    \"value\": \"3e69c0572c1eddf7f232cf60f6b8634194bf40d09aa9535c78430e64df407ec4\"
                },
                \"ca_certs\": {},
                \"capacity_concurrency\": {
                    \"value\": \"10\"
                },
                \"capacity_memory\": {
                    \"value\": \"512\"
                },
                \"custom_image_tag\": {
                    \"value\": \"hashicorp/build-worker:now\"
                },
                \"disk_path\": {},
                \"enable_active_active\": {
                    \"value\": \"0\"
                },
                \"enable_metrics_collection\": {
                    \"value\": \"1\"
                },
                \"enc_password\": {
                    \"value\": \"${enc_password}\"
                },
                \"extern_vault_addr\": {},
                \"extern_vault_enable\": {
                    \"value\": \"0\"
                },
                \"extern_vault_path\": {},
                \"extern_vault_propagate\": {},
                \"extern_vault_role_id\": {},
                \"extern_vault_secret_id\": {},
                \"extern_vault_token_renew\": {},
                \"extra_no_proxy\": {},
                \"force_tls\": {
                    \"value\": \"0\"
                },
                \"gcs_bucket\": {},
                \"gcs_credentials\": {
                    \"value\": \"{}\"
                },
                \"gcs_project\": {},
                \"hairpin_addressing\": {
                    \"value\": \"0\"
                },
                \"hostname\": {
                    \"value\": \"${hostname}\"
                },
                \"iact_subnet_list\": {},
                \"iact_subnet_time_limit\": {
                    \"value\": \"60\"
                },
                \"installation_type\": {
                    \"value\": \"production\"
                },
                \"pg_dbname\": {
                    \"value\": \"mydbtfe\"
                },
                \"pg_extra_params\": {
                    \"value\": \"sslmode=disable\"
                },
                \"pg_netloc\": {
                    \"value\": \"${pgsqlhostname}\"
                },
                \"pg_password\": {
                    \"value\": \"${pgsqlpassword}\"
                },
                \"pg_user\": {
                    \"value\": \"${pguser}\"
                },
                \"placement\": {
                    \"value\": \"placement_s3\"
                },
                \"production_type\": {
                    \"value\": \"external\"
                },
                \"redis_host\": {},
                \"redis_pass\": {
                    \"value\": \"NGVITSiZJKkmtC9ed1XWjScsVZMnXJx5\"
                },
                \"redis_port\": {},
                \"redis_use_password_auth\": {},
                \"redis_use_tls\": {},
                \"restrict_worker_metadata_access\": {
                    \"value\": \"0\"
                },
                \"s3_bucket\": {
                    \"value\": \"${s3bucket}\"
                },
                \"s3_endpoint\": {},
                \"s3_region\": {
                    \"value\": \"${s3region}\"
                },
                \"s3_sse\": {},
                \"s3_sse_kms_key_id\": {},
                \"tbw_image\": {
                    \"value\": \"default_image\"
                },
                \"tls_ciphers\": {},
                \"tls_vers\": {
                    \"value\": \"tls_1_2_tls_1_3\"
                }
            }
            " > /home/ubuntu/install/settings.json
            
            echo "
            {
                \"DaemonAuthenticationType\":     \"password\",
                \"DaemonAuthenticationPassword\": \"Password1#\",
                \"TlsBootstrapType\":             \"server-path\",
                \"TlsBootstrapHostname\":         \"${hostname}\",
                \"TlsBootstrapCert\":             \"/home/ubuntu/install/server.crt\",
                \"TlsBootstrapKey\":              \"/home/ubuntu/install/server.key\",
                \"BypassPreflightChecks\":        true,
                \"ImportSettingsFrom\":           \"/home/ubuntu/install/settings.json\",
                \"LicenseFileLocation\":          \"/home/ubuntu/install/license.rli\",
                \"LicenseBootstrapAirgapPackagePath\": \"/home/ubuntu/install/tfe-557.airgap\"
            }" > /home/ubuntu/install/replicated.conf
            echo "${cert_pem}" > /home/ubuntu/install/server.crt
            echo "${key_pem}" > /home/ubuntu/install/server.key
            IPADDR=$(hostname -I | awk '{print $1}')
            echo "#!/usr/bin/env bash
            chmod 600 /home/ubuntu/install/server.key
            cd /home/ubuntu/install
            aws s3 cp s3://aakulov-aws5-tfe-airgap . --recursive --no-progress
            tar -xf latest.tar.gz
            sudo rm -rf /usr/share/keyrings/docker-archive-keyring.gpg
            cp /home/ubuntu/install/replicated.conf /etc/replicated.conf
            cp /home/ubuntu/install/replicated.conf /root/replicated.conf
            chown -R ubuntu: /home/ubuntu/install
            
            yes | sudo ./install.sh airgap no-proxy private-address=$IPADDR public-address=$IPADDR" &>> /home/ubuntu/install/install_tfe.sh
            
            chmod +x /home/ubuntu/install/install_tfe.sh
            
            sh /home/ubuntu/install/install_tfe.sh &>> /home/ubuntu/install/install_tfe.log
            
            date >> /home/ubuntu/install/install_tfe.log
            
            cat /home/ubuntu/install/install_tfe.log >> /home/ubuntu/install/$EC2_INSTANCE_ID.log
            
            cat /home/ubuntu/install/curl_output.log >> /home/ubuntu/install/$EC2_INSTANCE_ID.log
            
            aws s3 cp /home/ubuntu/install/$EC2_INSTANCE_ID.log s3://aakulov-aws5-tfe-logs/$EC2_INSTANCE_ID.log 
        EOT
      + vars     = {
          + "cert_pem"      = (known after apply)
          + "enc_password"  = (sensitive)
          + "hostname"      = "tfe5.anton.hashicorp-success.com"
          + "key_pem"       = (sensitive)
          + "pgsqlhostname" = (known after apply)
          + "pgsqlpassword" = (sensitive)
          + "pguser"        = "postgres"
          + "s3bucket"      = "aakulov-aws5-tfe-data"
          + "s3region"      = "eu-central-1"
        }
    }

  # aws_acm_certificate.aws5 will be created
  + resource "aws_acm_certificate" "aws5" {
      + arn                       = (known after apply)
      + domain_name               = "tfe5.anton.hashicorp-success.com"
      + domain_validation_options = [
          + {
              + domain_name           = "tfe5.anton.hashicorp-success.com"
              + resource_record_name  = (known after apply)
              + resource_record_type  = (known after apply)
              + resource_record_value = (known after apply)
            },
        ]
      + id                        = (known after apply)
      + status                    = (known after apply)
      + subject_alternative_names = (known after apply)
      + tags_all                  = (known after apply)
      + validation_emails         = (known after apply)
      + validation_method         = "DNS"
    }

  # aws_acm_certificate_validation.aws5 will be created
  + resource "aws_acm_certificate_validation" "aws5" {
      + certificate_arn = (known after apply)
      + id              = (known after apply)
    }

  # aws_autoscaling_group.aws5 will be created
  + resource "aws_autoscaling_group" "aws5" {
      + arn                       = (known after apply)
      + availability_zones        = (known after apply)
      + default_cooldown          = (known after apply)
      + desired_capacity          = (known after apply)
      + force_delete              = true
      + force_delete_warm_pool    = false
      + health_check_grace_period = 400
      + health_check_type         = (known after apply)
      + id                        = (known after apply)
      + launch_configuration      = (known after apply)
      + max_size                  = 2
      + metrics_granularity       = "1Minute"
      + min_size                  = 1
      + name                      = (known after apply)
      + name_prefix               = "aakulov-aws5-asg"
      + placement_group           = (known after apply)
      + protect_from_scale_in     = false
      + service_linked_role_arn   = (known after apply)
      + tags                      = [
          + {
              + "key"                 = "Name"
              + "propagate_at_launch" = "true"
              + "value"               = "aakulov-aws5-asg#"
            },
        ]
      + target_group_arns         = (known after apply)
      + vpc_zone_identifier       = (known after apply)
      + wait_for_capacity_timeout = "10m"

      + timeouts {
          + delete = "15m"
        }

      + warm_pool {
          + max_group_prepared_capacity = 1
          + min_size                    = 1
          + pool_state                  = "Running"
        }
    }

  # aws_db_instance.aws5 will be created
  + resource "aws_db_instance" "aws5" {
      + address                               = (known after apply)
      + allocated_storage                     = 20
      + apply_immediately                     = (known after apply)
      + arn                                   = (known after apply)
      + auto_minor_version_upgrade            = true
      + availability_zone                     = (known after apply)
      + backup_retention_period               = (known after apply)
      + backup_window                         = (known after apply)
      + ca_cert_identifier                    = (known after apply)
      + character_set_name                    = (known after apply)
      + copy_tags_to_snapshot                 = false
      + db_subnet_group_name                  = "aakulov-aws5"
      + delete_automated_backups              = true
      + endpoint                              = (known after apply)
      + engine                                = "postgres"
      + engine_version                        = "12.7"
      + engine_version_actual                 = (known after apply)
      + hosted_zone_id                        = (known after apply)
      + id                                    = (known after apply)
      + identifier                            = (known after apply)
      + identifier_prefix                     = (known after apply)
      + instance_class                        = "db.t3.medium"
      + kms_key_id                            = (known after apply)
      + latest_restorable_time                = (known after apply)
      + license_model                         = (known after apply)
      + maintenance_window                    = (known after apply)
      + max_allocated_storage                 = 100
      + monitoring_interval                   = 0
      + monitoring_role_arn                   = (known after apply)
      + multi_az                              = (known after apply)
      + name                                  = "mydbtfe"
      + nchar_character_set_name              = (known after apply)
      + option_group_name                     = (known after apply)
      + parameter_group_name                  = (known after apply)
      + password                              = (sensitive value)
      + performance_insights_enabled          = false
      + performance_insights_kms_key_id       = (known after apply)
      + performance_insights_retention_period = (known after apply)
      + port                                  = (known after apply)
      + publicly_accessible                   = false
      + replicas                              = (known after apply)
      + resource_id                           = (known after apply)
      + skip_final_snapshot                   = true
      + snapshot_identifier                   = (known after apply)
      + status                                = (known after apply)
      + storage_type                          = (known after apply)
      + tags                                  = {
          + "Name" = "aakulov-aws5"
        }
      + tags_all                              = {
          + "Name" = "aakulov-aws5"
        }
      + timezone                              = (known after apply)
      + username                              = "postgres"
      + vpc_security_group_ids                = (known after apply)
    }

  # aws_db_subnet_group.aws5 will be created
  + resource "aws_db_subnet_group" "aws5" {
      + arn         = (known after apply)
      + description = "Managed by Terraform"
      + id          = (known after apply)
      + name        = "aakulov-aws5"
      + name_prefix = (known after apply)
      + subnet_ids  = (known after apply)
      + tags        = {
          + "Name" = "aakulov-aws5"
        }
      + tags_all    = {
          + "Name" = "aakulov-aws5"
        }
    }

  # aws_eip.eip1 will be created
  + resource "aws_eip" "eip1" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = (known after apply)
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags                 = {
          + "Name" = "aakulov-aws5-1"
        }
      + tags_all             = {
          + "Name" = "aakulov-aws5-1"
        }
      + vpc                  = true
    }

  # aws_eip.eip2 will be created
  + resource "aws_eip" "eip2" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = (known after apply)
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags                 = {
          + "Name" = "aakulov-aws5-2"
        }
      + tags_all             = {
          + "Name" = "aakulov-aws5-2"
        }
      + vpc                  = true
    }

  # aws_iam_instance_profile.aakulov-aws5-ec2-s3 will be created
  + resource "aws_iam_instance_profile" "aakulov-aws5-ec2-s3" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = "aakulov-aws5-ec2-s3"
      + path        = "/"
      + role        = "aakulov-aws5-iam-role-ec2-s3"
      + tags_all    = (known after apply)
      + unique_id   = (known after apply)
    }

  # aws_iam_role.aakulov-aws5-iam-role-ec2-s3 will be created
  + resource "aws_iam_role" "aakulov-aws5-iam-role-ec2-s3" {
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
      + name                  = "aakulov-aws5-iam-role-ec2-s3"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags                  = {
          + "tag-key" = "aakulov-aws5-iam-role-ec2-s3"
        }
      + tags_all              = {
          + "tag-key" = "aakulov-aws5-iam-role-ec2-s3"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # aws_iam_role_policy.aakulov-aws5-ec2-s3 will be created
  + resource "aws_iam_role_policy" "aakulov-aws5-ec2-s3" {
      + id     = (known after apply)
      + name   = "aakulov-aws5-ec2-s3"
      + policy = (known after apply)
      + role   = (known after apply)
    }

  # aws_internet_gateway.igw will be created
  + resource "aws_internet_gateway" "igw" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = {
          + "Name" = "aakulov-aws5"
        }
      + tags_all = {
          + "Name" = "aakulov-aws5"
        }
      + vpc_id   = (known after apply)
    }

  # aws_launch_configuration.aws5 will be created
  + resource "aws_launch_configuration" "aws5" {
      + arn                         = (known after apply)
      + associate_public_ip_address = false
      + ebs_optimized               = (known after apply)
      + enable_monitoring           = true
      + iam_instance_profile        = (known after apply)
      + id                          = (known after apply)
      + image_id                    = "ami-0a3ca16f3cf729915"
      + instance_type               = "t3.large"
      + key_name                    = "aakulov"
      + name                        = (known after apply)
      + name_prefix                 = "aakulov-aws5-asg"
      + security_groups             = (known after apply)
      + user_data                   = (known after apply)

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + no_device             = (known after apply)
          + snapshot_id           = (known after apply)
          + throughput            = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + metadata_options {
          + http_endpoint               = (known after apply)
          + http_put_response_hop_limit = (known after apply)
          + http_tokens                 = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + throughput            = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
    }

  # aws_lb.aws5 will be created
  + resource "aws_lb" "aws5" {
      + arn                        = (known after apply)
      + arn_suffix                 = (known after apply)
      + dns_name                   = (known after apply)
      + drop_invalid_header_fields = false
      + enable_deletion_protection = false
      + enable_http2               = true
      + id                         = (known after apply)
      + idle_timeout               = 60
      + internal                   = false
      + ip_address_type            = (known after apply)
      + load_balancer_type         = "application"
      + name                       = "aakulov-aws5"
      + security_groups            = (known after apply)
      + subnets                    = (known after apply)
      + tags_all                   = (known after apply)
      + vpc_id                     = (known after apply)
      + zone_id                    = (known after apply)

      + subnet_mapping {
          + allocation_id        = (known after apply)
          + ipv6_address         = (known after apply)
          + outpost_id           = (known after apply)
          + private_ipv4_address = (known after apply)
          + subnet_id            = (known after apply)
        }
    }

  # aws_lb_listener.aws5-443 will be created
  + resource "aws_lb_listener" "aws5-443" {
      + arn               = (known after apply)
      + certificate_arn   = (known after apply)
      + id                = (known after apply)
      + load_balancer_arn = (known after apply)
      + port              = 443
      + protocol          = "HTTPS"
      + ssl_policy        = "ELBSecurityPolicy-FS-1-2-Res-2020-10"
      + tags_all          = (known after apply)

      + default_action {
          + order            = (known after apply)
          + target_group_arn = (known after apply)
          + type             = "forward"
        }
    }

  # aws_lb_listener.aws5-8800 will be created
  + resource "aws_lb_listener" "aws5-8800" {
      + arn               = (known after apply)
      + certificate_arn   = (known after apply)
      + id                = (known after apply)
      + load_balancer_arn = (known after apply)
      + port              = 8800
      + protocol          = "HTTPS"
      + ssl_policy        = "ELBSecurityPolicy-FS-1-2-Res-2020-10"
      + tags_all          = (known after apply)

      + default_action {
          + order            = (known after apply)
          + target_group_arn = (known after apply)
          + type             = "forward"
        }
    }

  # aws_lb_target_group.aws5-443 will be created
  + resource "aws_lb_target_group" "aws5-443" {
      + arn                                = (known after apply)
      + arn_suffix                         = (known after apply)
      + deregistration_delay               = "300"
      + id                                 = (known after apply)
      + lambda_multi_value_headers_enabled = false
      + load_balancing_algorithm_type      = (known after apply)
      + name                               = "aakulov-aws5-443"
      + port                               = 443
      + preserve_client_ip                 = (known after apply)
      + protocol                           = "HTTPS"
      + protocol_version                   = (known after apply)
      + proxy_protocol_v2                  = false
      + slow_start                         = 400
      + tags_all                           = (known after apply)
      + target_type                        = "instance"
      + vpc_id                             = (known after apply)

      + health_check {
          + enabled             = (known after apply)
          + healthy_threshold   = (known after apply)
          + interval            = (known after apply)
          + matcher             = (known after apply)
          + path                = (known after apply)
          + port                = (known after apply)
          + protocol            = (known after apply)
          + timeout             = (known after apply)
          + unhealthy_threshold = (known after apply)
        }

      + stickiness {
          + cookie_duration = (known after apply)
          + cookie_name     = (known after apply)
          + enabled         = (known after apply)
          + type            = (known after apply)
        }
    }

  # aws_lb_target_group.aws5-8800 will be created
  + resource "aws_lb_target_group" "aws5-8800" {
      + arn                                = (known after apply)
      + arn_suffix                         = (known after apply)
      + deregistration_delay               = "300"
      + id                                 = (known after apply)
      + lambda_multi_value_headers_enabled = false
      + load_balancing_algorithm_type      = (known after apply)
      + name                               = "aakulov-aws5-8800"
      + port                               = 8800
      + preserve_client_ip                 = (known after apply)
      + protocol                           = "HTTPS"
      + protocol_version                   = (known after apply)
      + proxy_protocol_v2                  = false
      + slow_start                         = 400
      + tags_all                           = (known after apply)
      + target_type                        = "instance"
      + vpc_id                             = (known after apply)

      + health_check {
          + enabled             = (known after apply)
          + healthy_threshold   = (known after apply)
          + interval            = (known after apply)
          + matcher             = (known after apply)
          + path                = (known after apply)
          + port                = (known after apply)
          + protocol            = (known after apply)
          + timeout             = (known after apply)
          + unhealthy_threshold = (known after apply)
        }

      + stickiness {
          + cookie_duration = (known after apply)
          + cookie_name     = (known after apply)
          + enabled         = (known after apply)
          + type            = (known after apply)
        }
    }

  # aws_nat_gateway.nat1 will be created
  + resource "aws_nat_gateway" "nat1" {
      + allocation_id        = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Name" = "aakulov-aws5-1"
        }
      + tags_all             = {
          + "Name" = "aakulov-aws5-1"
        }
    }

  # aws_nat_gateway.nat2 will be created
  + resource "aws_nat_gateway" "nat2" {
      + allocation_id        = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Name" = "aakulov-aws5-2"
        }
      + tags_all             = {
          + "Name" = "aakulov-aws5-2"
        }
    }

  # aws_placement_group.aws5 will be created
  + resource "aws_placement_group" "aws5" {
      + arn                = (known after apply)
      + id                 = (known after apply)
      + name               = "aws5"
      + placement_group_id = (known after apply)
      + strategy           = "spread"
      + tags_all           = (known after apply)
    }

  # aws_route53_record.aws5 will be created
  + resource "aws_route53_record" "aws5" {
      + allow_overwrite = true
      + fqdn            = (known after apply)
      + id              = (known after apply)
      + name            = "tfe5.anton.hashicorp-success.com"
      + records         = (known after apply)
      + ttl             = 300
      + type            = "CNAME"
      + zone_id         = "Z077919913NMEBCGB4WS0"
    }

  # aws_route53_record.cert_validation["tfe5.anton.hashicorp-success.com"] will be created
  + resource "aws_route53_record" "cert_validation" {
      + allow_overwrite = true
      + fqdn            = (known after apply)
      + id              = (known after apply)
      + name            = (known after apply)
      + records         = (known after apply)
      + ttl             = 60
      + type            = (known after apply)
      + zone_id         = "Z077919913NMEBCGB4WS0"
    }

  # aws_route_table.aws5-private-1 will be created
  + resource "aws_route_table" "aws5-private-1" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + carrier_gateway_id         = ""
              + cidr_block                 = "0.0.0.0/0"
              + destination_prefix_list_id = ""
              + egress_only_gateway_id     = ""
              + gateway_id                 = ""
              + instance_id                = ""
              + ipv6_cidr_block            = ""
              + local_gateway_id           = ""
              + nat_gateway_id             = (known after apply)
              + network_interface_id       = ""
              + transit_gateway_id         = ""
              + vpc_endpoint_id            = ""
              + vpc_peering_connection_id  = ""
            },
        ]
      + tags             = {
          + "Name" = "aakulov-aws5-private-1"
        }
      + tags_all         = {
          + "Name" = "aakulov-aws5-private-1"
        }
      + vpc_id           = (known after apply)
    }

  # aws_route_table.aws5-private-2 will be created
  + resource "aws_route_table" "aws5-private-2" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + carrier_gateway_id         = ""
              + cidr_block                 = "0.0.0.0/0"
              + destination_prefix_list_id = ""
              + egress_only_gateway_id     = ""
              + gateway_id                 = ""
              + instance_id                = ""
              + ipv6_cidr_block            = ""
              + local_gateway_id           = ""
              + nat_gateway_id             = (known after apply)
              + network_interface_id       = ""
              + transit_gateway_id         = ""
              + vpc_endpoint_id            = ""
              + vpc_peering_connection_id  = ""
            },
        ]
      + tags             = {
          + "Name" = "aakulov-aws5-private-2"
        }
      + tags_all         = {
          + "Name" = "aakulov-aws5-private-2"
        }
      + vpc_id           = (known after apply)
    }

  # aws_route_table.aws5-public-1 will be created
  + resource "aws_route_table" "aws5-public-1" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + carrier_gateway_id         = ""
              + cidr_block                 = "0.0.0.0/0"
              + destination_prefix_list_id = ""
              + egress_only_gateway_id     = ""
              + gateway_id                 = (known after apply)
              + instance_id                = ""
              + ipv6_cidr_block            = ""
              + local_gateway_id           = ""
              + nat_gateway_id             = ""
              + network_interface_id       = ""
              + transit_gateway_id         = ""
              + vpc_endpoint_id            = ""
              + vpc_peering_connection_id  = ""
            },
        ]
      + tags             = {
          + "Name" = "aakulov-aws5-public-1"
        }
      + tags_all         = {
          + "Name" = "aakulov-aws5-public-1"
        }
      + vpc_id           = (known after apply)
    }

  # aws_route_table.aws5-public-2 will be created
  + resource "aws_route_table" "aws5-public-2" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + carrier_gateway_id         = ""
              + cidr_block                 = "0.0.0.0/0"
              + destination_prefix_list_id = ""
              + egress_only_gateway_id     = ""
              + gateway_id                 = (known after apply)
              + instance_id                = ""
              + ipv6_cidr_block            = ""
              + local_gateway_id           = ""
              + nat_gateway_id             = ""
              + network_interface_id       = ""
              + transit_gateway_id         = ""
              + vpc_endpoint_id            = ""
              + vpc_peering_connection_id  = ""
            },
        ]
      + tags             = {
          + "Name" = "aakulov-aws5-public-2"
        }
      + tags_all         = {
          + "Name" = "aakulov-aws5-public-2"
        }
      + vpc_id           = (known after apply)
    }

  # aws_route_table_association.aws5-private-1 will be created
  + resource "aws_route_table_association" "aws5-private-1" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_route_table_association.aws5-private-2 will be created
  + resource "aws_route_table_association" "aws5-private-2" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_route_table_association.aws5-public-1 will be created
  + resource "aws_route_table_association" "aws5-public-1" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_route_table_association.aws5-public-2 will be created
  + resource "aws_route_table_association" "aws5-public-2" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_s3_bucket.data will be created
  + resource "aws_s3_bucket" "data" {
      + acceleration_status         = (known after apply)
      + acl                         = "private"
      + arn                         = (known after apply)
      + bucket                      = "aakulov-aws5-tfe-data"
      + bucket_domain_name          = (known after apply)
      + bucket_regional_domain_name = (known after apply)
      + force_destroy               = false
      + hosted_zone_id              = (known after apply)
      + id                          = (known after apply)
      + region                      = (known after apply)
      + request_payer               = (known after apply)
      + tags                        = {
          + "Name" = "aakulov-aws5-tfe-data"
        }
      + tags_all                    = {
          + "Name" = "aakulov-aws5-tfe-data"
        }
      + website_domain              = (known after apply)
      + website_endpoint            = (known after apply)

      + versioning {
          + enabled    = true
          + mfa_delete = false
        }
    }

  # aws_s3_bucket.logs will be created
  + resource "aws_s3_bucket" "logs" {
      + acceleration_status         = (known after apply)
      + acl                         = "private"
      + arn                         = (known after apply)
      + bucket                      = "aakulov-aws5-tfe-logs"
      + bucket_domain_name          = (known after apply)
      + bucket_regional_domain_name = (known after apply)
      + force_destroy               = true
      + hosted_zone_id              = (known after apply)
      + id                          = (known after apply)
      + region                      = (known after apply)
      + request_payer               = (known after apply)
      + tags                        = {
          + "Name" = "aakulov-aws5-tfe-logs"
        }
      + tags_all                    = {
          + "Name" = "aakulov-aws5-tfe-logs"
        }
      + website_domain              = (known after apply)
      + website_endpoint            = (known after apply)

      + versioning {
          + enabled    = true
          + mfa_delete = false
        }
    }

  # aws_s3_bucket_public_access_block.data will be created
  + resource "aws_s3_bucket_public_access_block" "data" {
      + block_public_acls       = true
      + block_public_policy     = true
      + bucket                  = (known after apply)
      + id                      = (known after apply)
      + ignore_public_acls      = true
      + restrict_public_buckets = true
    }

  # aws_s3_bucket_public_access_block.logs will be created
  + resource "aws_s3_bucket_public_access_block" "logs" {
      + block_public_acls       = true
      + block_public_policy     = true
      + bucket                  = (known after apply)
      + id                      = (known after apply)
      + ignore_public_acls      = true
      + restrict_public_buckets = true
    }

  # aws_security_group.aws5-internal-sg will be created
  + resource "aws_security_group" "aws5-internal-sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = -1
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "icmp"
              + security_groups  = []
              + self             = false
              + to_port          = -1
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 8800
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 8800
            },
          + {
              + cidr_blocks      = []
              + description      = ""
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = (known after apply)
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = []
              + description      = ""
              + from_port        = 8800
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = (known after apply)
              + self             = false
              + to_port          = 8800
            },
        ]
      + name                   = "aakulov-aws5-internal-sg"
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "aakulov-aws5-internal-sg"
        }
      + tags_all               = {
          + "Name" = "aakulov-aws5-internal-sg"
        }
      + vpc_id                 = (known after apply)
    }

  # aws_security_group.aws5-lb-sg will be created
  + resource "aws_security_group" "aws5-lb-sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 8800
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 8800
            },
        ]
      + name                   = "aakulov-aws5-lb-sg"
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "aakulov-aws5-lb-sg"
        }
      + tags_all               = {
          + "Name" = "aakulov-aws5-lb-sg"
        }
      + vpc_id                 = (known after apply)
    }

  # aws_security_group.aws5-public-sg will be created
  + resource "aws_security_group" "aws5-public-sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 80
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 80
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 8800
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 8800
            },
          + {
              + cidr_blocks      = []
              + description      = ""
              + from_port        = 5432
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = true
              + to_port          = 5432
            },
        ]
      + name                   = "aakulov-aws5-public-sg"
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "aakulov-aws5-public-sg"
        }
      + tags_all               = {
          + "Name" = "aakulov-aws5-public-sg"
        }
      + vpc_id                 = (known after apply)
    }

  # aws_security_group_rule.aws5-lb-sg-to-aws5-internal-sg-allow-443 will be created
  + resource "aws_security_group_rule" "aws5-lb-sg-to-aws5-internal-sg-allow-443" {
      + from_port                = 443
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "egress"
    }

  # aws_security_group_rule.aws5-lb-sg-to-aws5-internal-sg-allow-8800 will be created
  + resource "aws_security_group_rule" "aws5-lb-sg-to-aws5-internal-sg-allow-8800" {
      + from_port                = 8800
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 8800
      + type                     = "egress"
    }

  # aws_subnet.subnet_private1 will be created
  + resource "aws_subnet" "subnet_private1" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1b"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.5.1.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags                            = {
          + "Name" = "aakulov-aws5-private-1"
        }
      + tags_all                        = {
          + "Name" = "aakulov-aws5-private-1"
        }
      + vpc_id                          = (known after apply)
    }

  # aws_subnet.subnet_private2 will be created
  + resource "aws_subnet" "subnet_private2" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1c"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.5.3.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags                            = {
          + "Name" = "aakulov-aws5-private-2"
        }
      + tags_all                        = {
          + "Name" = "aakulov-aws5-private-2"
        }
      + vpc_id                          = (known after apply)
    }

  # aws_subnet.subnet_public1 will be created
  + resource "aws_subnet" "subnet_public1" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1b"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.5.2.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags                            = {
          + "Name" = "aakulov-aws5-public-1"
        }
      + tags_all                        = {
          + "Name" = "aakulov-aws5-public-1"
        }
      + vpc_id                          = (known after apply)
    }

  # aws_subnet.subnet_public2 will be created
  + resource "aws_subnet" "subnet_public2" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1c"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.5.4.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags                            = {
          + "Name" = "aakulov-aws5-public-2"
        }
      + tags_all                        = {
          + "Name" = "aakulov-aws5-public-2"
        }
      + vpc_id                          = (known after apply)
    }

  # aws_vpc.vpc will be created
  + resource "aws_vpc" "vpc" {
      + arn                              = (known after apply)
      + assign_generated_ipv6_cidr_block = false
      + cidr_block                       = "10.5.0.0/16"
      + default_network_acl_id           = (known after apply)
      + default_route_table_id           = (known after apply)
      + default_security_group_id        = (known after apply)
      + dhcp_options_id                  = (known after apply)
      + enable_classiclink               = (known after apply)
      + enable_classiclink_dns_support   = (known after apply)
      + enable_dns_hostnames             = true
      + enable_dns_support               = true
      + id                               = (known after apply)
      + instance_tenancy                 = "default"
      + ipv6_association_id              = (known after apply)
      + ipv6_cidr_block                  = (known after apply)
      + main_route_table_id              = (known after apply)
      + owner_id                         = (known after apply)
      + tags                             = {
          + "Name" = "aakulov-aws5"
        }
      + tags_all                         = {
          + "Name" = "aakulov-aws5"
        }
    }

  # tls_private_key.aws5 will be created
  + resource "tls_private_key" "aws5" {
      + algorithm                  = "RSA"
      + ecdsa_curve                = "P224"
      + id                         = (known after apply)
      + private_key_pem            = (sensitive value)
      + public_key_fingerprint_md5 = (known after apply)
      + public_key_openssh         = (known after apply)
      + public_key_pem             = (known after apply)
      + rsa_bits                   = 2048
    }

  # tls_self_signed_cert.aws5 will be created
  + resource "tls_self_signed_cert" "aws5" {
      + allowed_uses          = [
          + "key_encipherment",
          + "digital_signature",
          + "server_auth",
        ]
      + cert_pem              = (known after apply)
      + dns_names             = [
          + "tfe5.anton.hashicorp-success.com",
        ]
      + early_renewal_hours   = 744
      + id                    = (known after apply)
      + key_algorithm         = "RSA"
      + private_key_pem       = (sensitive value)
      + ready_for_renewal     = true
      + validity_end_time     = (known after apply)
      + validity_period_hours = 8928
      + validity_start_time   = (known after apply)

      + subject {
          + common_name  = "tfe5.anton.hashicorp-success.com"
          + organization = "aakulov sandbox"
        }
    }

Plan: 46 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + aws_url = "tfe5.anton.hashicorp-success.com"

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

tls_private_key.aws5: Creating...
tls_private_key.aws5: Creation complete after 0s [id=bb19d927c37dd651ce0b072e007adb2d2664b472]
tls_self_signed_cert.aws5: Creating...
tls_self_signed_cert.aws5: Creation complete after 0s [id=208778101584717657975481217353614200118]
aws_placement_group.aws5: Creating...
aws_eip.eip2: Creating...
aws_eip.eip1: Creating...
aws_vpc.vpc: Creating...
aws_iam_role.aakulov-aws5-iam-role-ec2-s3: Creating...
aws_acm_certificate.aws5: Creating...
aws_s3_bucket.logs: Creating...
aws_s3_bucket.data: Creating...
aws_placement_group.aws5: Creation complete after 1s [id=aws5]
aws_eip.eip2: Creation complete after 1s [id=eipalloc-e0421de2]
aws_eip.eip1: Creation complete after 1s [id=eipalloc-01782703]
aws_iam_role.aakulov-aws5-iam-role-ec2-s3: Creation complete after 2s [id=aakulov-aws5-iam-role-ec2-s3]
aws_iam_instance_profile.aakulov-aws5-ec2-s3: Creating...
aws_s3_bucket.logs: Creation complete after 3s [id=aakulov-aws5-tfe-logs]
aws_s3_bucket_public_access_block.logs: Creating...
aws_iam_instance_profile.aakulov-aws5-ec2-s3: Creation complete after 1s [id=aakulov-aws5-ec2-s3]
aws_s3_bucket.data: Creation complete after 3s [id=aakulov-aws5-tfe-data]
aws_s3_bucket_public_access_block.data: Creating...
aws_iam_role_policy.aakulov-aws5-ec2-s3: Creating...
aws_s3_bucket_public_access_block.logs: Creation complete after 1s [id=aakulov-aws5-tfe-logs]
aws_s3_bucket_public_access_block.data: Creation complete after 1s [id=aakulov-aws5-tfe-data]
aws_iam_role_policy.aakulov-aws5-ec2-s3: Creation complete after 1s [id=aakulov-aws5-iam-role-ec2-s3:aakulov-aws5-ec2-s3]
aws_vpc.vpc: Still creating... [10s elapsed]
aws_acm_certificate.aws5: Still creating... [10s elapsed]
aws_acm_certificate.aws5: Creation complete after 11s [id=arn:aws:acm:eu-central-1:267023797923:certificate/6856584f-06fc-4e4e-b6e1-512882522363]
aws_acm_certificate_validation.aws5: Creating...
aws_route53_record.cert_validation["tfe5.anton.hashicorp-success.com"]: Creating...
aws_vpc.vpc: Creation complete after 12s [id=vpc-085ac6ee2f777c6a6]
aws_internet_gateway.igw: Creating...
aws_subnet.subnet_private2: Creating...
aws_subnet.subnet_private1: Creating...
aws_subnet.subnet_public1: Creating...
aws_lb_target_group.aws5-8800: Creating...
aws_lb_target_group.aws5-443: Creating...
aws_security_group.aws5-lb-sg: Creating...
aws_security_group.aws5-public-sg: Creating...
aws_subnet.subnet_private1: Creation complete after 1s [id=subnet-018d496dcc3e0e414]
aws_subnet.subnet_private2: Creation complete after 1s [id=subnet-092152e90f9547ecd]
aws_subnet.subnet_public2: Creating...
aws_db_subnet_group.aws5: Creating...
aws_internet_gateway.igw: Creation complete after 1s [id=igw-04c68b3d56b9e7f92]
aws_lb_target_group.aws5-8800: Creation complete after 1s [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:targetgroup/aakulov-aws5-8800/be6d3acf7bcf03ab]
aws_route_table.aws5-public-1: Creating...
aws_route_table.aws5-public-2: Creating...
aws_subnet.subnet_public1: Creation complete after 1s [id=subnet-04bf8e9a94a4a7795]
aws_lb_target_group.aws5-443: Creation complete after 1s [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:targetgroup/aakulov-aws5-443/01c0512b234e2d95]
aws_nat_gateway.nat1: Creating...
aws_subnet.subnet_public2: Creation complete after 1s [id=subnet-01cfa4164d51452a5]
aws_nat_gateway.nat2: Creating...
aws_db_subnet_group.aws5: Creation complete after 1s [id=aakulov-aws5]
aws_security_group.aws5-lb-sg: Creation complete after 2s [id=sg-01f685cbb0bbf478f]
aws_lb.aws5: Creating...
aws_security_group.aws5-internal-sg: Creating...
aws_security_group.aws5-public-sg: Creation complete after 2s [id=sg-0e6dad61a94eed598]
aws_route_table.aws5-public-1: Creation complete after 1s [id=rtb-0646bffeab4596a00]
aws_route_table_association.aws5-public-1: Creating...
aws_route_table.aws5-public-2: Creation complete after 1s [id=rtb-01297ab95e06d650f]
aws_route_table_association.aws5-public-2: Creating...
aws_route_table_association.aws5-public-1: Creation complete after 1s [id=rtbassoc-05f868037eb2b1af7]
aws_route_table_association.aws5-public-2: Creation complete after 0s [id=rtbassoc-0d01cad170c06f3e1]
aws_security_group.aws5-internal-sg: Creation complete after 2s [id=sg-0d865e6f8bf004062]
aws_security_group_rule.aws5-lb-sg-to-aws5-internal-sg-allow-443: Creating...
aws_security_group_rule.aws5-lb-sg-to-aws5-internal-sg-allow-8800: Creating...
aws_db_instance.aws5: Creating...
aws_security_group_rule.aws5-lb-sg-to-aws5-internal-sg-allow-443: Creation complete after 1s [id=sgrule-793125566]
aws_security_group_rule.aws5-lb-sg-to-aws5-internal-sg-allow-8800: Creation complete after 1s [id=sgrule-3110278211]
aws_acm_certificate_validation.aws5: Still creating... [10s elapsed]
aws_route53_record.cert_validation["tfe5.anton.hashicorp-success.com"]: Still creating... [10s elapsed]
aws_nat_gateway.nat1: Still creating... [10s elapsed]
aws_nat_gateway.nat2: Still creating... [10s elapsed]
aws_lb.aws5: Still creating... [10s elapsed]
aws_db_instance.aws5: Still creating... [10s elapsed]
aws_acm_certificate_validation.aws5: Creation complete after 18s [id=2021-11-04 13:11:11.295 +0000 UTC]
aws_route53_record.cert_validation["tfe5.anton.hashicorp-success.com"]: Still creating... [20s elapsed]
aws_nat_gateway.nat1: Still creating... [20s elapsed]
aws_nat_gateway.nat2: Still creating... [20s elapsed]
aws_lb.aws5: Still creating... [20s elapsed]
aws_db_instance.aws5: Still creating... [20s elapsed]
aws_route53_record.cert_validation["tfe5.anton.hashicorp-success.com"]: Still creating... [30s elapsed]
aws_nat_gateway.nat1: Still creating... [31s elapsed]
aws_nat_gateway.nat2: Still creating... [30s elapsed]
aws_lb.aws5: Still creating... [30s elapsed]
aws_db_instance.aws5: Still creating... [30s elapsed]
aws_route53_record.cert_validation["tfe5.anton.hashicorp-success.com"]: Still creating... [40s elapsed]
aws_route53_record.cert_validation["tfe5.anton.hashicorp-success.com"]: Creation complete after 42s [id=Z077919913NMEBCGB4WS0__bc821ed9619411501044be7d888a152c.tfe5.anton.hashicorp-success.com._CNAME]
aws_nat_gateway.nat1: Still creating... [41s elapsed]
aws_nat_gateway.nat2: Still creating... [40s elapsed]
aws_lb.aws5: Still creating... [40s elapsed]
aws_db_instance.aws5: Still creating... [40s elapsed]
aws_nat_gateway.nat1: Still creating... [51s elapsed]
aws_nat_gateway.nat2: Still creating... [50s elapsed]
aws_lb.aws5: Still creating... [50s elapsed]
aws_db_instance.aws5: Still creating... [50s elapsed]
aws_nat_gateway.nat1: Still creating... [1m1s elapsed]
aws_nat_gateway.nat2: Still creating... [1m0s elapsed]
aws_lb.aws5: Still creating... [1m0s elapsed]
aws_db_instance.aws5: Still creating... [1m0s elapsed]
aws_nat_gateway.nat1: Still creating... [1m11s elapsed]
aws_nat_gateway.nat2: Still creating... [1m10s elapsed]
aws_lb.aws5: Still creating... [1m10s elapsed]
aws_db_instance.aws5: Still creating... [1m10s elapsed]
aws_nat_gateway.nat1: Still creating... [1m21s elapsed]
aws_nat_gateway.nat2: Still creating... [1m20s elapsed]
aws_lb.aws5: Still creating... [1m20s elapsed]
aws_db_instance.aws5: Still creating... [1m20s elapsed]
aws_nat_gateway.nat1: Creation complete after 1m26s [id=nat-0e3d0f330ce384e5c]
aws_route_table.aws5-private-1: Creating...
aws_route_table.aws5-private-1: Creation complete after 1s [id=rtb-065e0b6edcf5b5e70]
aws_route_table_association.aws5-private-1: Creating...
aws_route_table_association.aws5-private-1: Creation complete after 1s [id=rtbassoc-03a610ec684fb3bc5]
aws_nat_gateway.nat2: Still creating... [1m30s elapsed]
aws_lb.aws5: Still creating... [1m30s elapsed]
aws_db_instance.aws5: Still creating... [1m30s elapsed]
aws_nat_gateway.nat2: Creation complete after 1m35s [id=nat-0415f40aff89b1d40]
aws_route_table.aws5-private-2: Creating...
aws_route_table.aws5-private-2: Creation complete after 2s [id=rtb-0f55deca19c228576]
aws_route_table_association.aws5-private-2: Creating...
aws_route_table_association.aws5-private-2: Creation complete after 0s [id=rtbassoc-03d5a28f2af6891f2]
aws_lb.aws5: Still creating... [1m40s elapsed]
aws_db_instance.aws5: Still creating... [1m40s elapsed]
aws_lb.aws5: Still creating... [1m50s elapsed]
aws_db_instance.aws5: Still creating... [1m50s elapsed]
aws_lb.aws5: Still creating... [2m0s elapsed]
aws_db_instance.aws5: Still creating... [2m0s elapsed]
aws_lb.aws5: Still creating... [2m10s elapsed]
aws_db_instance.aws5: Still creating... [2m10s elapsed]
aws_lb.aws5: Still creating... [2m20s elapsed]
aws_db_instance.aws5: Still creating... [2m20s elapsed]
aws_lb.aws5: Still creating... [2m30s elapsed]
aws_db_instance.aws5: Still creating... [2m30s elapsed]
aws_lb.aws5: Still creating... [2m40s elapsed]
aws_db_instance.aws5: Still creating... [2m40s elapsed]
aws_lb.aws5: Still creating... [2m50s elapsed]
aws_db_instance.aws5: Still creating... [2m50s elapsed]
aws_lb.aws5: Creation complete after 2m53s [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:loadbalancer/app/aakulov-aws5/50a007b0195d5529]
aws_route53_record.aws5: Creating...
aws_lb_listener.aws5-443: Creating...
aws_lb_listener.aws5-8800: Creating...
aws_lb_listener.aws5-443: Creation complete after 1s [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:listener/app/aakulov-aws5/50a007b0195d5529/00c497fe246df1f2]
aws_lb_listener.aws5-8800: Creation complete after 1s [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:listener/app/aakulov-aws5/50a007b0195d5529/f0ac174592cfb3d3]
aws_db_instance.aws5: Still creating... [3m0s elapsed]
aws_route53_record.aws5: Still creating... [10s elapsed]
aws_db_instance.aws5: Still creating... [3m10s elapsed]
aws_route53_record.aws5: Still creating... [20s elapsed]
aws_db_instance.aws5: Creation complete after 3m14s [id=terraform-20211104131103009500000002]
data.template_file.install_tfe_sh: Reading...
data.template_file.install_tfe_sh: Read complete after 0s [id=4d70b8d33b827aaf757f1bc00b0236137e0800cc0f63327db249a2955a1ddd51]
data.template_cloudinit_config.aws5_cloudinit: Reading...
data.template_cloudinit_config.aws5_cloudinit: Read complete after 0s [id=945278484]
aws_launch_configuration.aws5: Creating...
aws_launch_configuration.aws5: Creation complete after 1s [id=aakulov-aws5-asg20211104131417167100000003]
aws_autoscaling_group.aws5: Creating...
aws_route53_record.aws5: Still creating... [30s elapsed]
aws_autoscaling_group.aws5: Still creating... [10s elapsed]
aws_route53_record.aws5: Still creating... [40s elapsed]
aws_autoscaling_group.aws5: Still creating... [20s elapsed]
aws_route53_record.aws5: Creation complete after 49s [id=Z077919913NMEBCGB4WS0_tfe5.anton.hashicorp-success.com_CNAME]
aws_autoscaling_group.aws5: Creation complete after 29s [id=aakulov-aws5-asg20211104131417890000000004]

Apply complete! Resources: 46 added, 0 changed, 0 destroyed.

Outputs:

aws_url = "tfe5.anton.hashicorp-success.com"
```

## Usage

- Wait about 5-10 minutes until Terraform Enterprise instances are up and running and 502 Error code is not displayed

- Open the URL `https://tfe5.myname.hashicorp-success.com:8800/` in a web browser

- Expected result:

![TFE login page](https://github.com/antonakv/tf-ob-tfe-aws-airgap-asglb/raw/main/images/tf-ob-tfe-aws-airgap-asglb-1.png)

- Enter password ```Password1#``` and click ```Unlock```

- Expected result:

 ![Unlock](https://github.com/antonakv/tf-ob-tfe-aws-airgap-asglb/raw/main/images/tf-ob-tfe-aws-airgap-asglb-2.png)

- Click on `Dashboard`

- Expected result:

 ![Dashboard](https://github.com/antonakv/tf-ob-tfe-aws-airgap-asglb/raw/main/images/tf-ob-tfe-aws-airgap-asglb-3.png)
