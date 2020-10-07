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
bats -p boundary/
```
