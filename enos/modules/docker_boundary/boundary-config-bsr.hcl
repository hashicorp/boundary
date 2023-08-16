# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

disable_mlock = true

controller {
  name        = "docker-controller"

  database {
    url = "env://BOUNDARY_POSTGRES_URL"
  }
}

listener "tcp" {
  address     = "boundary:9200"
  purpose     = "api"
  tls_disable = true
}

listener "tcp" {
  address     = "boundary:9201"
  purpose     = "cluster"
  tls_disable = true
}

listener "tcp" {
  address     = "boundary:9203"
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

kms "aead" {
  purpose   = "bsr"
  aead_type = "aes-gcm"
  key       = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
  key_id    = "global_recovery"
}
