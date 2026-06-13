terraform {
  required_version = ">= 1.6.0"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }
}

provider "hcloud" {}

data "hcloud_ssh_key" "founder" {
  name = var.ssh_key_name
}

resource "hcloud_server" "reeve_phase1" {
  name        = var.server_name
  image       = var.image
  server_type = var.server_type
  location    = var.location
  ssh_keys    = [data.hcloud_ssh_key.founder.id]
  user_data   = file("${path.module}/cloud-init.yml")

  labels = {
    purpose = "reeve-phase1-validation"
  }
}

