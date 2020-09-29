#!/bin/bash
# Runs Boundary integration tests against an arbitrary Boundary instance denoted
# by BOUNDARY_ADDR. If BOUNDARY_ADDR is unset, this test suite will run the 
# Boundary test controller library.
#
# If BOUNDARY_ADDR is set to localhost or 127.0.0.1, the test suite will override
# this value with docker.host.internal in order for the boundary binary being 
# executed within docker to reach the docker host localhost.
#
# Examples 
#    Running Boundary locally in dev mode and executing this test suite
#    against it:
#
#    BOUNDARY_ADDR=http://127.0.0.1:9200 ./run.sh
#
#    Running this test suite against the test controller library:
#
#    unset BOUNDARY_ADDR && ./run.sh
#
BOUNDARY_ADDR="${BOUNDARY_ADDR:-''}" \

# BOUNDARY_BUILD defaults to false, and if set, will run the docker build suite
# to build the binary locally inside docker and make it available to the test 
# suite for running Boundary commands.
BOUNDARY_BUILD="${BOUNDARY_BUILD:-''}" \

# All test files in this library require the 'integration' tag to build and run.
go test -count=1 -v -tags integration .
