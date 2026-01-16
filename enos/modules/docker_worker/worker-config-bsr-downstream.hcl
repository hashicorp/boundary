# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

disable_mlock = true

listener "tcp" {
  address     = "0.0.0.0:${port}"
  purpose     = "proxy"
  tls_disable = true
}

listener "tcp" {
  address = "0.0.0.0:${port_ops}"
  purpose = "ops"
  tls_disable = true
}

worker {
  name = "${worker_name}"
  public_addr = "${worker_name}:${port}"
  initial_upstreams = ["${initial_upstream}"]

  tags {
    type = ${type_tags},
  }

  recording_storage_path = "${recording_storage_path}"
}

# This key_id needs to match the corresponding upstream worker's
# "downstream-worker-auth" kms
kms "aead" {
  purpose   = "worker-auth"
  aead_type = "aes-gcm"
  key       = "X+IJMVT6OnsrIR6G/9OTcJSX+lM9FSPN"
  key_id    = "downstream_worker-auth"
}

events {
  audit_enabled       = true
  sysevents_enabled   = true
  observations_enable = true

  sink "stderr" {
    name        = "all-events"
    description = "All events sent to stderr"
    event_types = ["*"]
    format      = "cloudevents-json"
  }

  sink {
    name = "Log File"
    event_types = ["*"]
    format = "cloudevents-json"

    file {
      path = "/boundary/logs"
      file_name = "events.log"
    }

    audit_config {
      audit_filter_overrides {
        secret    = "redact"
        sensitive = "redact"
      }
    }
  }
}
