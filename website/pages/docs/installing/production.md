### Controller Configuration

name must be unique!

### Worker Configuration

name must be unique!

### Installation

1. `/etc/boundary-${TYPE}.hcl`: Configuration file for the boundary service
1. `/usr/local/bin/boundary`: The Boundary binary
1. `/etc/systemd/system/boundary-${TYPE}.service`: Systemd unit file for the Boundary service

See `examples/aws/install/install.sh` for installing the Boundary binary as a service on systemd linux-type distributions.

See `examples/aws/ec2.tf` for configuration examples for the worker and controller respectively.
