# Quickstart with Docker-Compose
This directory contains the artifacts and resources for the docker-compose setup located in the following file `../docker-compose.dev.yaml`. It is especially useful if you need to start a preprovisioned Boundary environment and if you want to quickly test OIDC flow with an IdentityProvider (Keycloak). Furthermore an ssh server is also started and is ready to test the connect feature with it. 

## Setup
Add /etc/hosts entry for keycloak
```
127.0.0.1 keycloak
```

cd into the root directory of the repository 

excecute
```
make dev
```

start docker-compose
```
docker-compose -f docker-compose.dev.yaml up --build
```

Don't forget to cleanup with `docker-compose -f docker-compose.dev.yaml down` before next start

## Services

*   Boundary: 

    `http://localhost:9200`

    admin:admin123456


*   Keycloak: 

    `http://localhost:8080`

    admin:admin

*   Keycloak Realm Boundary User: 
    
    `http://localhost:8080/auth/realms/Boundary/account/#/` 
    
    Demo1:demo1

## UseCases
### Prerequisits
Installed boundary CLI
https://github.com/hashicorp/boundary/releases

### Authenticate to Boundary with Password

```
export BOUNDARY_TOKEN=`boundary authenticate password -auth-method-id=ampw_1234567890 -login-name=admin -password=admin123456 -keyring-type=none -format=json | jq -r '.item.attributes.token'`
```

### Authenticate to Boundary with IdentityProvider via OpenIdConnect

Authenticate with OIDC (Enter username:demo1 and password:demo1)
```
export AUTH_METHOD_KEYCLOAK=`boundary auth-methods list -format=json | jq -r '.items[] | select( .name == "keycloak" ) | .id'`

export BOUNDARY_TOKEN=`boundary authenticate oidc -auth-method-id ${AUTH_METHOD_KEYCLOAK} -format=json | jq -r '.item.attributes.token'`
```

###  Connect to SSH Server
You have to be authenticated first (BOUNDARY_TOKEN should be set)

```
export HOST_CATALOG_NAME="backend_servers"
export HOST_NAME="backend_server_service_ssh-testserver-01"

export HOST_CATALOG_ID=`boundary host-catalogs list -recursive -format json | jq -r ".items[] | select( .name == \"${HOST_CATALOG_NAME}\" ) | .id"`

export HOST_ID=`boundary hosts list -host-catalog-id=${HOST_CATALOG_ID} -format=json | jq -r ".items[] | select( .name == \"${HOST_NAME}\" ) | .id"`

boundary connect -target-scope-name="CoreInfra" -target-name="backend_servers_ssh" -host-id="${HOST_ID}" -listen-port=1234
```

Connect to ssh with `admin:password`
```
ssh admin@127.0.0.1 -p 1234
```

## Add/Modify Preprovisioning
* `./provisioning-terraform/scripts/main.tf`
* `./provisioning-script/scripts/provision-oidc.sh`

## Export Keycloak realm settings
If you change Keycloak settings and/or users and you want to persist them.
Execute following in the running Keycloak container

```
/opt/jboss/keycloak/bin/standalone.sh \
-Djboss.socket.binding.port-offset=100 -Dkeycloak.migration.action=export \
-Dkeycloak.migration.provider=singleFile \
-Dkeycloak.migration.realmName=Boundary \
-Dkeycloak.migration.usersExportStrategy=REALM_FILE \
-Dkeycloak.migration.file=/tmp/realm.json
```

Copy `/tmp/realm.json`
```
docker cp <containerId>:/tmp/realm.json /tmp/realm.json
```

