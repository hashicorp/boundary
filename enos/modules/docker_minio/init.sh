#!/usr/bin/env bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

# This script initializes a minio server to contain the necessary resources to test
SOURCE=$(realpath $(dirname ${BASH_SOURCE[0]})) # get directory of this script

docker pull $MINIO_CLIENT_IMAGE

docker run \
    --name minio-client \
    --rm \
    -e "MINIO_SERVER_CONTAINER_NAME=$MINIO_SERVER_CONTAINER_NAME" \
    -e "MINIO_ROOT_USER=$MINIO_ROOT_USER" \
    -e "MINIO_ROOT_PASSWORD=$MINIO_ROOT_PASSWORD" \
    -e "MINIO_REGION=$MINIO_REGION" \
    -e "MINIO_BUCKET_NAME=$MINIO_BUCKET_NAME" \
    -e "MINIO_USER_ID=$MINIO_USER_ID" \
    -e "MINIO_USER_PASSWORD=$MINIO_USER_PASSWORD" \
    -e "MINIO_USER_ACCESS_KEY_ID=$MINIO_USER_ACCESS_KEY_ID" \
    -e "MINIO_USER_SECRET_ACCESS_KEY=$MINIO_USER_SECRET_ACCESS_KEY" \
    --mount type=bind,src=$SOURCE,dst=/test \
    --network $TEST_NETWORK_NAME \
    --entrypoint bash \
    $MINIO_CLIENT_IMAGE \
    -c '
        mc alias set miniotest http://$MINIO_SERVER_CONTAINER_NAME:9000 ${MINIO_ROOT_USER} ${MINIO_ROOT_PASSWORD};
        mc admin config set miniotest region name=${MINIO_REGION};
        mc admin service restart miniotest;
        mc mb miniotest/${MINIO_BUCKET_NAME}
        mc admin user add miniotest ${MINIO_USER_ID} ${MINIO_USER_PASSWORD};
        mc admin policy create miniotest testpolicy /test/policy.json;
        mc admin policy attach miniotest testpolicy --user ${MINIO_USER_ID};
        mc admin user svcacct add miniotest ${MINIO_USER_ID} --access-key ${MINIO_USER_ACCESS_KEY_ID} --secret-key ${MINIO_USER_SECRET_ACCESS_KEY};
    '
