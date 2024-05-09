// controller.hcl
# Disable memory lock: https://www.man7.org/linux/man-pages/man2/mlock.2.html
disable_mlock = true

# Controller configuration block
controller {
  # This name attr must be unique across all controller instances if running in HA mode
  name = "demo-controller-1"
  description = "A controller for a demo!"

  # After receiving a shutdown signal, Boundary will wait 10s before initiating the shutdown process.
  graceful_shutdown_wait_duration = "10s"

  # Database URL for postgres. This can be a direct "postgres://"
  # URL, or it can be "file://" to read the contents of a file to
  # supply the url, or "env://" to name an environment variable
  # that contains the URL.
  database {
      url = "postgresql://boundary:boundary@127.0.0.1:5432"
  }
}

# API listener configuration block
listener "tcp" {
  # Should be the address of the NIC that the controller server will be reached on
  address = "0.0.0.0"
  # The purpose of this listener block
  purpose = "api"

  tls_disable = true

  # Uncomment to enable CORS for the Admin UI. Be sure to set the allowed origin(s)
  # to appropriate values.
  cors_enabled = false
  #cors_allowed_origins = ["https://yourcorp.yourdomain.com", "serve://boundary"]
}

# Data-plane listener configuration block (used for worker coordination)
listener "tcp" {
  # Should be the IP of the NIC that the worker will connect on
  address = "0.0.0.0"
  # The purpose of this listener
  purpose = "cluster"
  tls_disable = true
}

// change this if u needed
kms "aead" {
    purpose   = "root"
    aead_type = "aes-gcm"
    key       = "sP1fnF5Xz85RrXyELHFeZg9Ad2qt4Z4bgNHVGtD6ung="
    key_id    = "global_root"
}

// change this if u needed
kms "aead" {
    purpose   = "worker-auth"
    aead_type = "aes-gcm"
    key       = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
    key_id    = "global_worker-auth"
}

// change this if u needed
kms "aead" {
    purpose   = "recovery"
    aead_type = "aes-gcm"
    key       = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ=" 
    key_id    = "global_recovery"
}

events {
  observations_enabled = true
  sysevents_enabled = true
  telemetry_enabled = false
  sink "stderr" {
    name = "all-events"
    description = "All events sent to stderr"
    event_types = ["*"]
    format = "hclog-text"
  }
  sink "kafka" {
    name = "events-sink-kafka"
    description = "All events sent to Kafka"
    event_types = ["*"]
    format = "cloudevents-json"

    kafka_config {
      brokers = ["localhost:29092"]
      topic = "boundary-events"
    }
  }
}