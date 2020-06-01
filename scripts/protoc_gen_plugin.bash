#!/usr/bin/env bash

# Copied with minor changes from Makego at https://github.com/bufbuild/makego/blob/master/make/go/scripts/protoc_gen_plugin.bash

set -eo pipefail

fail() {
  echo "$@" >&2
  exit 1
}

usage() {
  echo "usage: ${0} \
    --proto_path=path/to/one \
    --proto_path=path/to/two \
    --proto_include_path=path/to/one \
    --proto_include_path=path/to/two \
    --plugin_name=go \
    --plugin_out=gen/proto/go \
    --plugin_opt=plugins=grpc"
}

check_flag_value_set() {
  if [ -z "${1}" ]; then
    usage
    exit 1
  fi
}

PROTO_PATHS=()
PROTO_INCLUDE_PATHS=()
PLUGIN_NAME=
PLUGIN_OUT=
PLUGIN_OPT=
while test $# -gt 0; do
  case "${1}" in
    -h|--help)
      usage
      exit 0
      ;;
    --proto_path*)
      PROTO_PATHS+=("$(echo ${1} | sed -e 's/^[^=]*=//g')")
      shift
      ;;
    --proto_include_path*)
      PROTO_INCLUDE_PATHS+=("$(echo ${1} | sed -e 's/^[^=]*=//g')")
      shift
      ;;
    --plugin_name*)
      PLUGIN_NAME="$(echo ${1} | sed -e 's/^[^=]*=//g')"
      shift
      ;;
    --plugin_out*)
      PLUGIN_OUT="$(echo ${1} | sed -e 's/^[^=]*=//g')"
      shift
      ;;
    --plugin_opt*)
      PLUGIN_OPT="$(echo ${1} | sed -e 's/^[^=]*=//g')"
      shift
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

check_flag_value_set "${PROTO_PATHS[@]}"
check_flag_value_set "${PLUGIN_NAME}"
check_flag_value_set "${PLUGIN_OUT}"

PROTOC_FLAGS=()
for proto_path in "${PROTO_PATHS[@]}"; do
  PROTOC_FLAGS+=("--proto_path=${proto_path}")
done
for proto_path in "${PROTO_INCLUDE_PATHS[@]}"; do
  PROTOC_FLAGS+=("--proto_path=${proto_path}")
done
PROTOC_FLAGS+=("--${PLUGIN_NAME}_out=${PLUGIN_OUT}")
if [ -n "${PLUGIN_OPT}" ]; then
  PROTOC_FLAGS+=("--${PLUGIN_NAME}_opt=${PLUGIN_OPT}")
fi

for proto_path in "${PROTO_PATHS[@]}"; do
  for dir in $(find "${proto_path}" -name '*.proto' -print0 | xargs -0 -n1 dirname | sort | uniq); do
    echo protoc "${PROTOC_FLAGS[@]}" $(find "${dir}" -name '*.proto')
    protoc "${PROTOC_FLAGS[@]}" $(find "${dir}" -name '*.proto')
  done
done
