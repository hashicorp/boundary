#!/usr/bin/env bash

set -eux -o pipefail

# accept either a JOB_PATH env var or script
JOB="${JOB_PATH:=$1}"

function retry {
  local retries=$1
  shift
  local count=0

  echo "$@"

  until "$@"; do
    exit=$?
    wait=$((2 ** count))
    count=$((count + 1))

    if [ "$count" -lt "$retries" ]; then
      sleep "$wait"
    else
      return "$exit"
    fi
  done

  return 0
}

function wait_for_eval_complete {
  nomad eval status -json "$1" | jq -e '(.Status == "complete")' > /dev/null
}

function wait_for_deploy_success {
  nomad deployment status -json "$1" | jq -e '(.Status == "successful")' > /dev/null
}

function is_batch {
  nomad eval status -json "$1" | jq -e '(.Type == "batch")' > /dev/null
}

echo "registering controller job: $JOB"
result=$(nomad job run -detach "${JOB}")

if test $?
then
  eval_id=$(echo "$result" | grep  "Evaluation ID" | cut -d ":" -f 2 | xargs)

  echo "waiting for eval: [$eval_id] to be complete"
  retry 5 wait_for_eval_complete "$eval_id"
  echo "eval: [$eval_id] complete"

  if is_batch "$eval_id"
  then
    echo "Batch jobs don't deploy, skipping status"
    exit 0
  fi

  deployment_id=$(nomad eval status -json "$eval_id" | jq -r .DeploymentID)

  echo "waiting for deployment: [$deployment_id] to be successful"
  retry 10 wait_for_deploy_success "$deployment_id"
  echo "deployment: [$deployment_id] successful"

  exit 0
fi

echo "deployment failed"
exit 1
