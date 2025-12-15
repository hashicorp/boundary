# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

listener "tcp" {
  purpose     = "proxy"
  tls_disable = true
  address     = "${listener_address}:9202"
}

worker {
  # Name attr must be unique across workers
  name = "demo-worker-${id}"
  description = "Enos Boundary worker ${id}"

  # Workers must be able to reach controllers on :9201
  initial_upstreams = ${controller_ips}

  public_addr = "${public_address}"

  tags {
    type   = ${type}
    region = ["${region}"]
  }

  recording_storage_path = "${recording_storage_path}"
}

# must be same key as used on controller config
kms "transit" {
  purpose            = "worker-auth"
  address            = "http://${vault_address}:8200"
  token              = "${vault_transit_token}"
  disable_renewal    = "false"
  key_name           = "boundary-worker-auth"
  mount_path         = "transit/"
  tls_skip_verify    = "true"
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
