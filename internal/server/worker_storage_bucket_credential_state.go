// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"

	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

type RemoteStorageState string

const (
	RemoteStorageStateAvailable RemoteStorageState = "available"
	RemoteStorageStateError     RemoteStorageState = "error"
	RemoteStorageStateUnknown   RemoteStorageState = "unknown"
)

func (t RemoteStorageState) String() string {
	switch t {
	case RemoteStorageStateAvailable, RemoteStorageStateError:
		return string(t)
	}
	return string(RemoteStorageStateUnknown)
}

type StorageBucketCredentialPermissionType string

func (s StorageBucketCredentialPermissionType) String() string {
	return string(s)
}

type StorageBucketCredentialPermissionState string

func (s StorageBucketCredentialPermissionState) String() string {
	return string(s)
}

// ParseStateType converts the string value of a storage bucket credential
// state value and converts it into a integer type.
func ParseStateType(s string) (plgpb.StateType, error) {
	switch s {
	case PermissionStateOk.String():
		return plgpb.StateType_STATE_TYPE_OK, nil
	case PermissionStateError.String():
		return plgpb.StateType_STATE_TYPE_ERROR, nil
	case PermissionStateUnknown.String():
		return plgpb.StateType_STATE_TYPE_UNKNOWN, nil
	default:
		return plgpb.StateType_STATE_TYPE_UNSPECIFIED, fmt.Errorf("undefined state value")
	}
}

// ParsePermissionState converts the state type value into a string value.
func ParsePermissionState(s plgpb.StateType) (string, error) {
	switch s {
	case plgpb.StateType_STATE_TYPE_OK:
		return PermissionStateOk.String(), nil
	case plgpb.StateType_STATE_TYPE_ERROR:
		return PermissionStateError.String(), nil
	case plgpb.StateType_STATE_TYPE_UNKNOWN:
		return PermissionStateUnknown.String(), nil
	default:
		return "", fmt.Errorf("undefined state type")
	}
}

const (
	PermissionTypeWrite    StorageBucketCredentialPermissionType  = "write"
	PermissionTypeRead     StorageBucketCredentialPermissionType  = "read"
	PermissionTypeDelete   StorageBucketCredentialPermissionType  = "delete"
	PermissionStateOk      StorageBucketCredentialPermissionState = "ok"
	PermissionStateError   StorageBucketCredentialPermissionState = "error"
	PermissionStateUnknown StorageBucketCredentialPermissionState = "unknown"
)
