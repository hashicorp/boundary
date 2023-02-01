load _authorized_actions

function create_vault_ssh_certificate_library() {
  boundary credential-libraries \
    create vault-ssh-certificate $@
}

function update_vault_ssh_certificate_library() {
  boundary credential-libraries \
    update vault-ssh-certificate $@
}

function create_vault_generic_library() {
  boundary credential-libraries \
    create vault-generic $@
}

function create_vault_library() {
  boundary credential-libraries \
    create vault $@
}

function read_credential_library() {
  boundary credential-libraries read -id $1 -format json
}

function delete_credential_library() {
  boundary credential-libraries delete -id $1 -format json
}

function list_credential_libraries() {
  local csid=$1
  boundary credential-libraries list -credential-store-id $1 -format json
}

function credential_library_id() {
  local name=$1
  local csid=$2

  strip $(list_credential_libraries $csid | jq -c ".items[] | select(.name | contains(\"$name\")) | .[\"id\"]")
}
