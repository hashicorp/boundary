#/bin/bash
VERSION=$1

sudo apt-get update
sudo apt-get install -y unzip bats
sudo curl https://releases.hashicorp.com/boundary/${VERSION}/boundary_${VERSION}_linux_amd64.zip --output /tmp/boundary.zip
unzip -d /usr/bin /tmp/boundary.zip
sudo chmod 0755 /usr/bin/boundary
