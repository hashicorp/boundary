#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# This script is used for setting up and executing boundary e2e tests. It sets
# up `pass` as a password store (linux) so that boundary can use it to store
# auth tokens and installs the latest vault cli before executing the desired tests.

set -eux -o pipefail

# Install dependencies
apt update
# unzip is used to unzip boundary.zip
# pass is used to store the auth token from `boundary authenticate``
# lsb-release is used for adding the hashicorp apt source
# postgresql-client is used for postgres tests
# default-mysql-client is used for mysql tests
# wget is used for downloading external dependencies and repository keys
# apt-transport-https enables HTTPS transport for APT repositories
# curl and ca-certificates are required for some repository setups (e.g., MongoDB).
apt install unzip pass lsb-release postgresql-client default-mysql-client wget apt-transport-https curl ca-certificates -y

# Function to install Cassandra
install_cassandra() {
  apt install -y python3-venv
  python3 -m venv "$HOME/cqlsh-venv"
  "$HOME/cqlsh-venv/bin/pip" install --upgrade pip
  "$HOME/cqlsh-venv/bin/pip" install cqlsh
  export PATH="$HOME/cqlsh-venv/bin:$PATH"
}

# Install Cassandra
install_cassandra

# Install Redis
apt install redis-server -y

# Create a GPG key
export KEY_PW=boundary
gpg --generate-key --batch <<eoGpgConf
    %echo Started!
    Key-Type: RSA
    Key-Length: default
    Subkey-Type: RSA
    Name-Real: boundary
    Name-Comment: default
    Name-Email: default
    Expire-Date: 0
    Passphrase: $KEY_PW
    %commit
    %echo Done.
eoGpgConf

# Enable gpg-preset-passphrase so that key passwords can be saved
echo "allow-preset-passphrase" >> ~/.gnupg/gpg-agent.conf
gpg-connect-agent reloadagent /bye &>/dev/null

# Get information about the created keys
export lines=$(gpg --list-secret-keys --with-colons --with-keygrip)
export KEY_ID=""
while read -r line
do
  # Save the first key id to be used later
  if [[ $line =~ "fpr"* ]]; then
    if [[ $KEY_ID == "" ]]; then
      KEY_ID="$(echo "$line" | sed -r 's/fpr|://g')"
    fi
  fi

  # Cache the passphrases for the keys so passwords do not need to be entered
  if [[ $line =~ "grp"* ]]; then
    export KEYGRIP_ID="$(echo "$line" | sed -r 's/grp|://g')"
    /usr/lib/gnupg/gpg-preset-passphrase --preset -P $KEY_PW $KEYGRIP_ID
  fi
done <<< $lines

# Trust the key
touch /tmp/test.txt
gpg -a --encrypt -r $KEY_ID --trust-model always --batch --yes /tmp/test.txt
echo "trusted-key $KEY_ID" >> ~/.gnupg/gpg.conf

# Initialize the password store
pass init $KEY_ID &>/dev/null

# Install the vault cli
export vault_version="1.17.6"
export vault_arch=$(dpkg --print-architecture)
wget "https://releases.hashicorp.com/vault/${vault_version}/vault_${vault_version}_linux_${vault_arch}.zip" -O /tmp/vault.zip
unzip -o /tmp/vault.zip -d /usr/local/bin/
rm /tmp/vault.zip


# Install the docker cli
wget -O- https://download.docker.com/linux/debian/gpg | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(lsb_release -cs) stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
apt update
apt install docker-ce-cli -y

# Install MongoDB client (mongosh)
# Reference: https://www.mongodb.com/docs/mongodb-shell/install/#debian
wget -qO- https://www.mongodb.org/static/pgp/server-8.0.asc | tee /etc/apt/trusted.gpg.d/server-8.0.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/trusted.gpg.d/server-8.0.asc] https://repo.mongodb.org/apt/debian bookworm/mongodb-org/8.0 main" | tee /etc/apt/sources.list.d/mongodb-org-8.0.list
apt update
apt install -y mongodb-mongosh

# Run Tests
unzip -o /boundary.zip -d /usr/local/bin/
cd /src/boundary
go test -v -count=1 $TEST_PACKAGE -timeout $TEST_TIMEOUT | tee /testlogs/test-e2e-${TEST_PACKAGE##*/}.log
