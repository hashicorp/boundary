// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/server/store"
	"google.golang.org/protobuf/proto"
)

// Ensure WorkerSessionInfoRequest implements interfaces
var (
	_ db.VetForWriter         = (*WorkerSessionInfoRequest)(nil)
	_ oplog.ReplayableMessage = (*WorkerSessionInfoRequest)(nil)
)

// WorkerSessionInfoRequest contains the last time a worker daemon sent a status update for session information.
type WorkerSessionInfoRequest struct {
	*store.WorkerSessionInfoRequest
	tableName string `gorm:"-"`
}

// NewWorkerSessionInfoRequest create a new instance of a worker session information request.
// The LastStatusTime field is set to the current time.
func NewWorkerSessionInfoRequest(workerId string) *WorkerSessionInfoRequest {
	return &WorkerSessionInfoRequest{
		WorkerSessionInfoRequest: &store.WorkerSessionInfoRequest{
			WorkerId:        workerId,
			LastRequestTime: timestamp.Now(),
		},
	}
}

// WorkerSessionInfoRequest creates an empty in-memory instance of a worker session information request.
func AllocWorkerSessionInfoRequest() *WorkerSessionInfoRequest {
	return &WorkerSessionInfoRequest{
		WorkerSessionInfoRequest: &store.WorkerSessionInfoRequest{},
	}
}

func (w *WorkerSessionInfoRequest) Clone() *WorkerSessionInfoRequest {
	cp := proto.Clone(w.WorkerSessionInfoRequest)
	return &WorkerSessionInfoRequest{
		WorkerSessionInfoRequest: cp.(*store.WorkerSessionInfoRequest),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the worker storage bucket credential state
func (w *WorkerSessionInfoRequest) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "server.(WorkerSessionInfoRequest).VetForWrite"
	switch {
	case w == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing worker session info request")
	case w.WorkerId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing worker id")
	case w.LastRequestTime == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing last request timestamp")
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (w *WorkerSessionInfoRequest) TableName() string {
	if w.tableName != "" {
		return w.tableName
	}
	return "server_worker_session_info_request"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (w *WorkerSessionInfoRequest) SetTableName(n string) {
	w.tableName = n
}
