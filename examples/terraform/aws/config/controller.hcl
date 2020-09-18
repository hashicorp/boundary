disable_mlock = true

telemetry { 
  prometheus_retention_time = "24h"
  disable_hostname = true
}

controller {
  name = "demo-controller"
  description = "A controller for a demo!"
}

listener "tcp" {
  address = "0.0.0.0:9200"
	purpose = "api"
	tls_disable = true
	# proxy_protocol_behavior = "allow_authorized"
	# proxy_protocol_authorized_addrs = "127.0.0.1"
	cors_enabled = true
	cors_allowed_origins = ["*"]
}

listener "tcp" {
  address = "0.0.0.0:9201"
	purpose = "cluster"
	tls_disable = true
	# proxy_protocol_behavior = "allow_authorized"
	# proxy_protocol_authorized_addrs = "127.0.0.1"
}

kms "aead" {
	purpose = "root"
	aead_type = "aes-gcm"
	key = "sP1fnF5Xz85RrXyELHFeZg9Ad2qt4Z4bgNHVGtD6ung="
	key_id = "global_root"
}

kms "aead" {
	purpose = "worker-auth"
	aead_type = "aes-gcm"
	key = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
	key_id = "global_worker-auth"
}

kms "aead" {
	purpose = "recovery"
	aead_type = "aes-gcm"
	key = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
	key_id = "global_recovery"
}

# docker run --name some-postgres -p 5432:5432 -e POSTGRES_PASSWORD=easy -d postgres
database {
  url = "postgresql://postgres:easy@localhost:5432/postgres?sslmode=disable"
}
