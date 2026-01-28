# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

# disable memory from being swapped to disk
disable_mlock = true

# Increase log level for debugging
log_level = "debug"

# listener denoting this is a worker proxy
listener "tcp" {
  address = "0.0.0.0:9202"
  purpose = "proxy"
}

# worker block for configuring the specifics of the
# worker service
worker {
  public_addr = "${worker_public_ip}"
  name = "win-worker-0"
  initial_upstreams = ${controller_ip}
  tags {
    type = ["worker", "rdp", "windows"]
  }
}

# Events (logging) configuration. This
# configures logging for ALL events to both
# stderr and a file at ${test_dir}<boundary_use>.log
events {
  audit_enabled       = true
  sysevents_enabled   = true
  observations_enable = true
  sink "stderr" {
    name = "all-events"
    description = "All events sent to stderr"
    event_types = ["*"]
    format = "cloudevents-json"
  }
  sink {
    name = "file-sink"
    description = "All events sent to a file"
    event_types = ["*"]
    format = "cloudevents-json"
    file {
      path = "${test_dir}"
      file_name = "worker.log"
    }
    audit_config {
      audit_filter_overrides {
        sensitive = "redact"
        secret    = "redact"
      }
    }
  }
}

kms "awskms" {
  purpose    = "worker-auth"
  region     = "${aws_region}"
  kms_key_id = "${aws_kms_key}"
}
