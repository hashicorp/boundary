# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

disable_mlock = true

controller {
  name = "boundary-controller-${id}"
  description = "Enos Boundary controller ${id}"

  max_page_size = ${max_page_size}

  database {
    url = "postgresql://${dbuser}:${dbpass}@${dbhost}:${dbport}/${dbname}"
    max_open_connections = ${db_max_open_connections}
  }
}

# API listener configuration block
listener "tcp" {
  # Should be the address of the NIC that the controller server will be reached on
  address = "${listener_address}:${api_port}"
  # The purpose of this listener block
  purpose = "api"
  tls_disable = true

  # Uncomment to enable CORS for the Admin UI. Be sure to set the allowed origin(s)
  # to appropriate values.
  #cors_enabled = true
  #cors_allowed_origins = ["https://yourcorp.yourdomain.com", "serve://boundary"]
}

# API listener configuration block
listener "tcp" {
  address = "${listener_address}:${ops_port}"
  purpose = "ops"
  tls_disable = true
}

# Data-plane listener configuration block (used for worker coordination)
listener "tcp" {
  # Should be the IP of the NIC that the worker will connect on
  address = "${cluster_address}:${cluster_port}"
  # The purpose of this listener
  purpose = "cluster"
}

kms "transit" {
  purpose            = "worker-auth"
  address            = "http://${vault_address}:8200"
  token              = "${vault_transit_token}"
  disable_renewal    = "false"
  key_name           = "boundary-worker-auth"
  mount_path         = "transit/"
  tls_skip_verify    = "true"
}

kms "transit" {
  purpose            = "root"
  address            = "http://${vault_address}:8200"
  token              = "${vault_transit_token}"
  disable_renewal    = "false"
  key_name           = "boundary-root"
  mount_path         = "transit/"
  tls_skip_verify    = "true"
}

kms "transit" {
  purpose            = "recovery"
  address            = "http://${vault_address}:8200"
  token              = "${vault_transit_token}"
  disable_renewal    = "false"
  key_name           = "boundary-recovery"
  mount_path         = "transit/"
  tls_skip_verify    = "true"
}

kms "transit" {
  purpose            = "bsr"
  address            = "http://${vault_address}:8200"
  token              = "${vault_transit_token}"
  disable_renewal    = "false"
  key_name           = "boundary-bsr"
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
