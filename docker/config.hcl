disable_mlock = true

controller {
  name = "demo-controller-1"
  description = "A controller for a demo!"

  database {
    url = "env://BOUNDARY_POSTGRES_URL"
    #url = "postgresql://postgres:postgres@0.0.0.0:5432/postgres?sslmode=disable"
  }
}

worker {
  name = "demo-worker-1"
  description = "A default worker created demonstration"
  controllers = [
    "0.0.0.0",
  ]
  address = "0.0.0.0"
}

listener "tcp" {
  address = "0.0.0.0"
  purpose = "api"
  tls_disable = true 
}

listener "tcp" {
  address = "0.0.0.0"
  purpose = "cluster"
  tls_disable   = true 
}

listener "tcp" {
  address       = "0.0.0.0"
  purpose       = "proxy"
  tls_disable   = true 
}

# Root KMS configuration block: this is the root key for Boundary
# Use a production KMS such as AWS KMS in production installs
kms "aead" {
  purpose = "root"
  aead_type = "aes-gcm"
  key = "uC8zAQ3sLJ9o0ZlH5lWIgxNZrNn0FiFqYj4802VKLKQ="
  key_id = "global_root"
}

# Worker authorization KMS
# Use a production KMS such as AWS KMS for production installs
# This key is the same key used in the worker configuration
kms "aead" {
  purpose = "worker-auth"
  aead_type = "aes-gcm"
  key = "cOQ9fiszFoxu/c20HbxRQ5E9dyDM6PqMY1GwqVLihsI="
  key_id = "global_worker-auth"
}

# Recovery KMS block: configures the recovery key for Boundary
# Use a production KMS such as AWS KMS for production installs
kms "aead" {
  purpose = "recovery"
  aead_type = "aes-gcm"
  key = "nIRSASgoP91KmaEcg/EAaM4iAkksyB+Lkes0gzrLIRM="
  key_id = "global_recovery"
}
