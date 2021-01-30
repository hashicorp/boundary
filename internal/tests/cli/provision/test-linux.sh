#/bin/bash
/usr/bin/boundary dev &>/dev/null &
PID=$!

function cleanup() {
  kill -9 $PID
}
trap cleanup SIGEXIT SIGINT SIGKILL

sleep 5 # wait for boundary to start
bats /tests/
cleanup
