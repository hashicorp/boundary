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

hcp_boundary_cluster_id = "${hcp_boundary_cluster_id}"

# worker block for configuring the specifics of the
# worker service
worker {
  public_addr = "${worker_public_ip}"
  tags {
    type = ["worker", "rdp", "windows"]
  }

  auth_storage_path = "${test_dir}/worker"
  recording_storage_path = "${test_dir}/recordings"
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
