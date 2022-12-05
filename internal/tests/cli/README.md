# Boundary CLI Tests

This directory contains [bats tests](https://github.com/bats-core/bats-core) for testing the Boundary CLI against arbitrary Boundary deployments.
The tests are meant to mimic common workflows such as creating resources, and connecting to targets. Currently, the tests rely heavily on
generated resources when running Boundary in `dev` mode. In the future, we hope to remove this dependency and generate all resources through
the Boundary CLI from the outset.

The tests are designed to be idempotent.

## Getting Started

#### Dependencies

- [jq](https://stedolan.github.io/jq/)
- [bats](https://github.com/bats-core/bats-core)
- [netcat](https://nc110.sourceforge.io/)
- [boundary](https://github.com/hashicorp/boundary)

#### Running Tests

1. Start boundary in dev mode

```bash
boundary dev
```

or direct the tests towards an existing install by setting

```bash
export BOUNDARY_ADDR=<your_install>
```

2. Run the tests

```bash
# for an untagged non-version of boundary
bats -p boundary/

# for an official boundary version
IS_VERSION=true bats -p boundary/
```

## Running Tests Against Other Deployments

You can run this suite against an arbitrary cluster by overriding the following env vars:

```bash
DEFAULT_LOGIN=<my_login> \
DEFAULT_PASSWORD=<my_password> \
BOUNDARY_ADDR=http://boundary-test-controller-salmon-b70f2710539143b4.elb.us-east-1.amazonaws.com:9200 \
bats boundary/
```

~> Note that these tests currently expect generated resources to exist. Failure to run against a Boundary deployment that does
not have generated resources will result in a lot of test failures. Future work includes breaking thses tests out in a way
that makes them not dependent on generated resources.
