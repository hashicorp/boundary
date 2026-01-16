# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

disable_mlock = true

controller {
  name        = "controller0"
  description = "A controller"

  database {
    url = "env://LOAD_TEST_BOUNDARY_POSTGRES_URL"
  }
}

worker {
  name              = "worker0"
  description       = "A worker"
  address           = "boundary"
  initial_upstreams = ["boundary:9201"]
}

listener "tcp" {
  address     = "boundary"
  purpose     = "api"
  tls_disable = true
}

listener "tcp" {
  address     = "boundary"
  purpose     = "cluster"
  tls_disable = true
}

listener "tcp" {
  address     = "boundary"
  purpose     = "proxy"
  tls_disable = true
}

listener "tcp" {
  address     = "boundary"
  purpose     = "ops"
  tls_disable = true
}

kms "aead" {
  purpose   = "root"
  aead_type = "aes-gcm"
  key       = "sP1fnF5Xz85RrXyELHFeZg9Ad2qt4Z4bgNHVGtD6ung="
  key_id    = "global_root"
}

kms "aead" {
  purpose   = "worker-auth"
  aead_type = "aes-gcm"
  key       = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
  key_id    = "global_worker-auth"
}

kms "aead" {
  purpose   = "recovery"
  aead_type = "aes-gcm"
  key       = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
  key_id    = "global_recovery"
}

reporting {
	license {
		enabled = false
  }
}
