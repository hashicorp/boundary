# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "target_count" {}
variable "enos_user" {}
variable "additional_labels" {
  default = {}
}
variable "instance_type" {
  description = "The type of instance to create."
  type        = string
  default     = "e2-micro"
}
variable "environment" {
  description = "Name of the environment."
  type        = string
  default     = "enos-environment"
}
variable "private_cidr_block" {
  type    = list(string)
  default = ["10.0.0.0/8"]
}
variable "gcp_zone" {
  description = "The zone to deploy the resources."
  type        = string
  default     = "us-central1-a"
}

data "enos_environment" "current" {}

resource "random_string" "test_string" {
  length  = 5
  lower   = true
  upper   = false
  numeric = false
  special = false
}

resource "google_compute_network" "boundary_compute_network" {
  name = "boundary-enos-network-${random_string.test_string.result}"
}

resource "random_id" "filter_label1" {
  prefix      = "enos_boundary"
  byte_length = 4
}

resource "random_id" "filter_label2" {
  prefix      = "enos_boundary"
  byte_length = 4
}

resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "google_compute_address" "boundary_external_ip" {
  count        = var.target_count
  name         = "boundary-external-ip-${random_string.test_string.result}-${count.index}"
  address_type = "EXTERNAL"
}

resource "google_compute_firewall" "boundary_private_ssh" {
  name          = "boundary-private-ssh-${random_string.test_string.result}"
  network       = google_compute_network.boundary_compute_network.name
  source_ranges = var.private_cidr_block
  target_tags   = ["boundary-target-${random_string.test_string.result}"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "boundary_enos_ssh" {
  name          = "boundary-enos-ssh-${random_string.test_string.result}"
  network       = google_compute_network.boundary_compute_network.name
  source_ranges = flatten([formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses)])
  target_tags   = ["boundary-target-${random_string.test_string.result}"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_instance" "boundary_target" {
  count        = var.target_count
  name         = "boundary-target-${random_string.test_string.result}-${count.index}"
  machine_type = var.instance_type
  zone         = var.gcp_zone

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
    }
  }

  network_interface {
    network = google_compute_network.boundary_compute_network.id

    access_config {
      nat_ip = google_compute_address.boundary_external_ip[count.index].address
    }
  }

  tags = ["boundary-target-${random_string.test_string.result}"]

  metadata = {
    ssh-keys = "ubuntu:${tls_private_key.ssh.public_key_openssh}"
  }

  labels = merge(var.additional_labels, {
    "name" : "boundary-target-${random_string.test_string.result}-${count.index}",
    "type" : "target",
    "project" : "enos",
    "project_name" : "qti-enos-boundary",
    "environment" : var.environment,
    "enos_user" : replace(lower(var.enos_user), "/[\\W]+/", ""),
    "filter_label_1" : random_id.filter_label1.hex
    "filter_label_2" : random_id.filter_label2.hex
  })
}

output "target_private_ips" {
  value = [for instance in google_compute_instance.boundary_target : instance.network_interface[0].network_ip]
}

output "target_public_ips" {
  value = [for instance in google_compute_instance.boundary_target : instance.network_interface[0].access_config[0].nat_ip]
}

output "target_ips" {
  value = flatten([
    [for instance in google_compute_instance.boundary_target : instance.network_interface[0].network_ip],
    [for instance in google_compute_instance.boundary_target : instance.network_interface[0].access_config[0].nat_ip]
  ])
}

output "target_ssh_key" {
  value     = tls_private_key.ssh.private_key_pem
  sensitive = true
}

output "filter_label1" {
  value = "labels.filter_label_1=${random_id.filter_label1.hex}"
}

output "filter_label2" {
  value = "labels.filter_label_2=${random_id.filter_label2.hex}"
}
