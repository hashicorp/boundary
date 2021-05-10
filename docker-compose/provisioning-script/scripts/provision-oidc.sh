#!/bin/ash

/bin/sleep 10

export BOUNDARY_ADDR="http://boundary:9200"
export CLIENT_FACING_BOUNDARY_URL="http://localhost:9200"

# Authenticate
export BOUNDARY_TOKEN=`boundary authenticate password -auth-method-id=ampw_1234567890 -login-name=admin -password=admin123456 -keyring-type=none -format=json | jq -r '.item.attributes.token'`

echo "TOKEN: ${BOUNDARY_TOKEN}"

# Create AuthMethod
boundary  auth-methods create oidc -issuer "http://keycloak:8080/auth/realms/Boundary" -client-id 'Boundary' -client-secret 'f609b4e3-d03a-47fe-bcb1-56130627ed75' -signing-algorithm RS256  -api-url-prefix ${CLIENT_FACING_BOUNDARY_URL} -name "keycloak"  

export AUTH_METHOD_KEYCLOAK=`boundary auth-methods list -format=json | jq -r '.items[] | select( .name == "keycloak" ) | .id'`

# Enable
boundary auth-methods change-state oidc  -id ${AUTH_METHOD_KEYCLOAK} -state active-public

export AUTH_METHOD_KEYCLOAK=`boundary auth-methods list -format=json | jq -r '.items[] | select( .name == "keycloak" ) | .id'`

# Create Account
boundary accounts create oidc -issuer=http://keycloak:8080/auth/realms/Boundary -subject=demo1 -auth-method-id=${AUTH_METHOD_KEYCLOAK} -name=demo1 -description=demo1

export DEMO1_ACCOUNT_ID=`boundary accounts list -auth-method-id=${AUTH_METHOD_KEYCLOAK} -format=json | jq -r '.items[] | select( .name == "demo1" ) | .id'`

# Add Account to Admin User
boundary users  add-accounts -id=u_1234567890 -account=${DEMO1_ACCOUNT_ID}

# Make Primary 
# boundary scopes update -id=global -primary-auth-method-id=${AUTH_METHOD_KEYCLOAK}
