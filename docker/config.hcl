disable_mlock = true

controller {
  name = "demo-controller-1"
  description = "A controller for a demo!"

  database {
    # This configuration setting requires the user to execute the container with the URL as an env var
    # to connect to the Boundary postgres DB. An example of how this can be done assuming the postgres 
    # database is running as a container and you're using docker for mac (replace host.docker.internal with
    # localhost if you're on linux):
    #    $  docker run -e 'BOUNDARY_POSTGRES_URL=postgresql://postgres:postgres@host.docker.internal:5432/postgres?sslmode=disable' [other options] boundary:[version]
    url = "env://BOUNDARY_POSTGRES_URL"
  }
}

worker {
  name = "demo-worker-1"
  description = "A default worker created demonstration"
}

listener "tcp" {
  # This configuration assumes the docker container hostname is being overridden using the --hostname
  # flag. The default configuration of a container uses the ephemeral container ID as the hostname and
  # this hostname resolves to the ephemeral IP of the container. We need to bind to the ephemeral IP 
  # of the container on startup, and need to know the hostname in order to do that. A future improvement
  # would be allowing the listener to set `env://HOSTNAME` as its value but that's not a feature at
  # the time of this writing. For now, when running boundary in docker you must pass the --hostname 
  # flag as:
  #    $ docker run --hostname boundary [other options] boundary:[version]
  address = "boundary"
  purpose = "api"
  tls_disable = true 
}

listener "tcp" {
  address = "boundary"
  purpose = "cluster"
  tls_disable   = true 
}

listener "tcp" {
  address = "boundary"
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
