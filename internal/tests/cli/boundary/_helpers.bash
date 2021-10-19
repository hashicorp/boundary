export BOUNDARY_ADDR="${BOUNDARY_ADDR:-http://127.0.0.1:9200}"
export DEFAULT_PASSWORD="${DEFAULT_PASSWORD:-password}"
export DEFAULT_LOGIN="${DEFAULT_LOGIN:-admin}"
export DEFAULT_UNPRIVILEGED_LOGIN="${DEFAULT_UNPRIVILEGED_LOGIN:-user}"
export DEFAULT_AMPW="${DEFAULT_AMPW:-ampw_1234567890}"
export DEFAULT_P_ID='p_1234567890'
export DEFAULT_O_ID='o_1234567890'
export DEFAULT_GLOBAL='global'
export DEFAULT_TARGET='ttcp_1234567890'
export DEFAULT_HOST_SET='hsst_1234567890'
export DEFAULT_HOST_CATALOG='hcst_1234567890'
export DEFAULT_HOST='hst_1234567890'
export DEFAULT_USER='u_1234567890'
export DEFAULT_UNPRIVILEGED_USER='u_0987654321'
export DEFAULT_GLOBAL='global'

function strip() {
  echo "$1" | tr -d '"'
}

function strip_all() {
  echo "$1" | tr -d '"' | tr -d '\'\'
}

function has_status_code() {
  local json=$1
  local code=$2
  if [ echo "$json"|jq -c ".status_code == $code" ]; then
    return 1
  fi

}