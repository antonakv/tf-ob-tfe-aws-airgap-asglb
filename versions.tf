terraform {
  required_version = "= 1.0.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 3.59"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "= 3.1.0"
    }
    template = {
      source  = "hashicorp/template"
      version = "= 2.2.0"
    }
  }
}
