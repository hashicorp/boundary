// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"database/sql"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// ListWorkerStorageBucketCredentialState returns a list of storage bucket credential states for the given worker.
func (r *Repository) ListWorkerStorageBucketCredentialState(ctx context.Context, workerId string, opts ...Option) (map[string]*plgpb.StorageBucketCredentialState, error) {
	const op = "server.(Repository).ListWorkerStorageBucketCredentialState"
	if workerId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty worker id")
	}
	type remoteStorageState struct {
		StorageBucketId string
		PermissionType  string
		State           string
		CheckedAt       *timestamp.Timestamp
		ErrorDetails    string
	}
	opt := GetOpts(opts...)
	reader := r.reader
	if !util.IsNil(opt.WithReader) {
		reader = opt.WithReader
	}
	rows, err := reader.Query(ctx, getStorageBucketCredentialStatesByWorkerId, []any{sql.Named("worker_id", workerId)})
	if err != nil && !errors.Match(errors.T(errors.RecordNotFound), err) {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()
	remoteStorageStates := map[string]*plgpb.StorageBucketCredentialState{}
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		var row remoteStorageState
		if err := reader.ScanRows(ctx, rows, &row); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch remote storage state"))
		}
		s, ok := remoteStorageStates[row.StorageBucketId]
		if !ok {
			s = &plgpb.StorageBucketCredentialState{
				State: &plgpb.Permissions{},
			}
		}
		state, err := ParseStateType(row.State)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		permissionState := &plgpb.Permission{
			State:        state,
			ErrorDetails: row.ErrorDetails,
			CheckedAt:    row.CheckedAt.GetTimestamp(),
		}
		switch row.PermissionType {
		case PermissionTypeWrite.String():
			s.State.Write = permissionState
		case PermissionTypeRead.String():
			s.State.Read = permissionState
		case PermissionTypeDelete.String():
			s.State.Delete = permissionState
		default:
			return nil, errors.New(ctx, errors.Internal, op, "unknown permission type")
		}
		remoteStorageStates[row.StorageBucketId] = s
	}
	return remoteStorageStates, nil
}
