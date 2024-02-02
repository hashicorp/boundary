# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

disable_mlock = true

controller {
  name = "boundary-controller-${id}"
  description = "Enos Boundary controller ${id}"
  database {
    url = "postgresql://${dbuser}:${dbpass}@${dbhost}:${dbport}/${dbname}"
    max_open_connections = ${db_max_open_connections}
  }
}

# API listener configuration block
listener "tcp" {
  # Should be the address of the NIC that the controller server will be reached on
  address = "${local_ipv4}:${api_port}"
  # The purpose of this listener block
  purpose = "api"
  tls_disable = true

  max_page_size = ${max_page_size}

  # Uncomment to enable CORS for the Admin UI. Be sure to set the allowed origin(s)
  # to appropriate values.
  #cors_enabled = true
  #cors_allowed_origins = ["https://yourcorp.yourdomain.com", "serve://boundary"]
}

# API listener configuration block
listener "tcp" {
  address = "${local_ipv4}:${ops_port}"
  purpose = "ops"
  tls_disable = true
}

# Data-plane listener configuration block (used for worker coordination)
listener "tcp" {
  # Should be the IP of the NIC that the worker will connect on
  address = "${local_ipv4}:${cluster_port}"
  # The purpose of this listener
  purpose = "cluster"
}

kms "awskms" {
  purpose    = "root"
  region     = "${region}"
  kms_key_id = "${kms_key_id}"
}

kms "awskms" {
  purpose    = "worker-auth"
  region     = "${region}"
  kms_key_id = "${kms_key_id}"
}
