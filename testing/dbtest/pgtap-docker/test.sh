#!/bin/sh
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1


function usage() { echo "Usage: $0 -h host -d database -p port -u username -w password -t 'tests/*.sql'" 1>&2; exit 1; }

while getopts d:h:p:u:w:b:n:t: OPTION
do
  case $OPTION in
    d)
      DATABASE=$OPTARG
      ;;
    h)
      HOST=$OPTARG
      ;;
    p)
      PORT=$OPTARG
      ;;
    u)
      USER=$OPTARG
      ;;
    w)
      PASSWORD=$OPTARG
      ;;
    t)
      TESTS=$OPTARG
      ;;
    H)
      usage
      ;;
  esac
done

echo "Waiting for database..."
timeout 240s sh -c "until pg_isready -h $HOST -p $PORT; do sleep 1; done"
echo

echo "Running tests: $TESTS"
# install pgtap
PGPASSWORD=$PASSWORD psql -q -h $HOST -p $PORT -d $DATABASE -U $USER -f /pgtap/sql/pgtap.sql

rc=$?
# exit if pgtap failed to install
if [[ $rc != 0 ]] ; then
  echo "pgTap was not installed properly. Unable to run tests!"
  exit $rc
fi
# run the tests
PGPASSWORD=$PASSWORD pg_prove -h $HOST -p $PORT -d $DATABASE -U $USER $TESTS
rc=$?
# uninstall pgtap
PGPASSWORD=$PASSWORD psql -q -h $HOST -p $PORT -d $DATABASE -U $USER -f /pgtap/sql/uninstall_pgtap.sql > /dev/null 2>&1
# exit with return code of the tests
exit $rc
