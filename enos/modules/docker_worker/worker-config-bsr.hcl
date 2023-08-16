# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

disable_mlock = true

telemetry {
  prometheus_retention_time = "24h"
  disable_hostname          = true
}

listener "tcp" {
  address     = "0.0.0.0:${port}"
  purpose     = "proxy"
  tls_disable = true
}

worker {
  name = "${worker_name}"
  initial_upstreams = ["${initial_upstream}"]

  tags {
    type = ${type_tags},
  }

  recording_storage_path = "${recording_storage_path}"
}

kms "aead" {
  purpose   = "worker-auth"
  aead_type = "aes-gcm"
  key       = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
  key_id    = "global_worker-auth"
}

kms "aead" {
  purpose   = "downstream-worker-auth"
  aead_type = "aes-gcm"
  key       = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
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
