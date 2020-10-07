export BOUNDARY_ADDR='http://127.0.0.1:9200'
export DEFAULT_PASSWORD='password'
export DEFAULT_USER='admin'
export DEFAULT_AMPW='ampw_1234567890'
export DEFAULT_P_ID='p_1234567890'
export DEFAULT_O_ID='o_1234567890'
export DEFAULT_TARGET='ttcp_1234567890'
export DEFAULT_HOST_SET='hsst_1234567890'

function strip() {
  echo "$1" | tr -d '"'
}
