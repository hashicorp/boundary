# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

listener "tcp" {
  purpose     = "proxy"
  tls_disable = true
  address     = "${listener_address}:${listener_proxy_port}"
}

hcp_boundary_cluster_id = "${hcp_boundary_cluster_id}"

worker {
  public_addr = "${public_address}"

  tags {
    type   = ${type}
    region = ["${region}"]
  }

  auth_storage_path = "${auth_storage_path}/worker"
  recording_storage_path = "${recording_storage_path}"
}

kms "awskms" {
  purpose    = "downstream-worker-auth"
  region     = "${region}"
  kms_key_id = "${kms_key_id}"
}

events {
  audit_enabled        = true
  observations_enabled = true
  sysevents_enabled    = true

  sink "stderr" {
    name        = "all-events"
    description = "All events sent to stderr"
    event_types = ["*"]
    format      = "cloudevents-json"

    deny_filters = [
      "\"/data/request_info/method\" contains \"Status\"",
      "\"/data/request_info/path\" contains \"/health\"",
    ]
  }

  sink {
    name        = "audit-sink"
    description = "Audit sent to a file"
    event_types = ["audit"]
    format      = "cloudevents-json"

    deny_filters = [
      "\"/data/request_info/method\" contains \"Status\"",
    ]

    file {
      path      = "${audit_log_dir}"
      file_name = "audit.log"
    }

    audit_config {
      audit_filter_overrides {
        secret    = "encrypt"
        sensitive = "hmac-sha256"
      }
    }
  }
}
