### Controller Configuration

Example controller configuration:

```hcl
# Disable memory lock: https://www.man7.org/linux/man-pages/man2/mlock.2.html
disable_mlock = true

telemetry {
  # TODO: prometheus is not currently implemented
  prometheus_retention_time = "24h"
  disable_hostname = true
}

# Controller configuration block
controller {
  # This name attr must be unique!
  name = "demo-controller-${count.index}"
  # Description of this controller
  description = "A controller for a demo!"
}

# API listener configuration block
listener "tcp" {
  # Should be the address of the NIC that the controller server will be reached on
  address = "${self.private_ip}:9200"
  # The purpose of this listener block
	purpose = "api"
  # Should be enabled for production installs
	tls_disable = true
  # TODO
	# proxy_protocol_behavior = "allow_authorized"
  # TODO
	# proxy_protocol_authorized_addrs = "127.0.0.1"
  # Enable CORS for the Admin UI
	cors_enabled = true
	cors_allowed_origins = ["*"]
}

# Data-plane listener configuration block (used for worker coordination)
listener "tcp" {
  # Should be the IP of the NIC that the worker will connect on
  address = "${self.private_ip}:9201"
  # The purpose of this listener
	purpose = "cluster"
  # Should be enabled for production installs
	tls_disable = true
  # TODO
	# proxy_protocol_behavior = "allow_authorized"
  # TODO
	# proxy_protocol_authorized_addrs = "127.0.0.1"
}

# Root KMS configuration block: this is the root key for Boundary
# Use a production KMS such as AWS KMS in production installs
kms "aead" {
	purpose = "root"
	aead_type = "aes-gcm"
	key = "sP1fnF5Xz85RrXyELHFeZg9Ad2qt4Z4bgNHVGtD6ung="
	key_id = "global_root"
}

# Worker authorization KMS
# Use a production KMS such as AWS KMS for production installs
# This key is the same key used in the worker configuration
kms "aead" {
	purpose = "worker-auth"
	aead_type = "aes-gcm"
	key = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
	key_id = "global_worker-auth"
}

# Recovery KMS block: configures the recovery key for Boundary
# Use a production KMS such as AWS KMS for production installs
kms "aead" {
	purpose = "recovery"
	aead_type = "aes-gcm"
	key = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
	key_id = "global_recovery"
}

# Database URL for postgres, can be overridden with PG_URL
database {
  url = "postgresql://boundary:boundarydemo@${aws_db_instance.boundary.endpoint}/boundary"
}
```

### Worker Configuration

```hcl
listener "tcp" {
	purpose = "proxy"
	tls_disable = true
	#proxy_protocol_behavior = "allow_authorized"
	#proxy_protocol_authorized_addrs = "127.0.0.1"
}

worker {
  # Name attr must be unique
	name = "demo-worker-${count.index}"
	description = "A default worker created demonstration"
	controllers = [
    "${aws_instance.controller[0].private_ip}",
    "${aws_instance.controller[1].private_ip}",
    "${aws_instance.controller[2].private_ip}"
  ]
}

# must be same key as used on controller config
kms "aead" {
	purpose = "worker-auth"
	aead_type = "aes-gcm"
	key = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
	key_id = "global_worker-auth"
}
```

name must be unique!

### Installation

`TYPE` below can be either `worker` or `controller`.

1. `/etc/boundary-${TYPE}.hcl`: Configuration file for the boundary service
   See above example configurations.

2. `/usr/local/bin/boundary`: The Boundary binary
   Can build from https://github.com/hashicorp/boundary or download binary from our release pages.

3. `/etc/systemd/system/boundary-${TYPE}.service`: Systemd unit file for the Boundary service
   Example:

```
[Unit]
Description=${NAME} ${TYPE}

[Service]
ExecStart=/usr/local/bin/${NAME} ${TYPE} -config /etc/${NAME}-${TYPE}.hcl

[Install]
WantedBy=multi-user.target
```

Here's a simple install script that installs the systemd unit file and enables it at startup:

```
# Installs the boundary as a service for systemd on linux
# Usage: ./install.sh <worker|controller>

TYPE=$1
NAME=boundary

sudo cat << EOF > /etc/systemd/system/${NAME}-${TYPE}.service
[Unit]
Description=${NAME} ${TYPE}

[Service]
ExecStart=/usr/local/bin/${NAME} ${TYPE} -config /etc/${NAME}-${TYPE}.hcl

[Install]
WantedBy=multi-user.target
EOF

sudo chmod 664 /etc/systemd/system/$NAME-$TYPE.service
sudo systemctl daemon-reload
sudo systemctl enable ${NAME}-${TYPE}
sudo systemctl start ${NAME}-${TYPE}
```
