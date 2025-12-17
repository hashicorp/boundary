// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"

	"github.com/fatih/structs"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

type (
	WorkerType        string
	OperationalState  string
	LocalStorageState string
)

const (
	UnknownWorkerType                     WorkerType        = "unknown"
	KmsWorkerType                         WorkerType        = "kms"
	PkiWorkerType                         WorkerType        = "pki"
	ActiveOperationalState                OperationalState  = "active"
	ShutdownOperationalState              OperationalState  = "shutdown"
	UnknownOperationalState               OperationalState  = "unknown"
	AvailableLocalStorageState            LocalStorageState = "available"
	LowStorageLocalStorageState           LocalStorageState = "low storage"
	CriticallyLowStorageLocalStorageState LocalStorageState = "critically low storage"
	OutOfStorageLocalStorageState         LocalStorageState = "out of storage"
	NotConfiguredLocalStorageState        LocalStorageState = "not configured"
	UnknownLocalStorageState              LocalStorageState = "unknown"
)

func (t WorkerType) Valid() bool {
	switch t {
	case KmsWorkerType, PkiWorkerType:
		return true
	}
	return false
}

func (t WorkerType) String() string {
	switch t {
	case KmsWorkerType, PkiWorkerType:
		return string(t)
	}
	return string(UnknownWorkerType)
}

type workerAuthWorkerId struct {
	WorkerId string `mapstructure:"worker_id"`
}

func ValidOperationalState(s string) bool {
	switch s {
	case ActiveOperationalState.String(), ShutdownOperationalState.String():
		return true
	}
	return false
}

func (t OperationalState) String() string {
	switch t {
	case ActiveOperationalState, ShutdownOperationalState:
		return string(t)
	}
	return string(UnknownOperationalState)
}

func ValidLocalStorageState(s string) bool {
	switch s {
	case AvailableLocalStorageState.String(), LowStorageLocalStorageState.String(),
		CriticallyLowStorageLocalStorageState.String(), OutOfStorageLocalStorageState.String(),
		NotConfiguredLocalStorageState.String(), UnknownLocalStorageState.String():
		return true
	}
	return false
}

func (t LocalStorageState) String() string {
	switch t {
	case AvailableLocalStorageState, LowStorageLocalStorageState,
		OutOfStorageLocalStorageState, NotConfiguredLocalStorageState,
		CriticallyLowStorageLocalStorageState:
		return string(t)
	}
	return string(UnknownLocalStorageState)
}

// AttachWorkerIdToState accepts a workerId and creates a struct for use with the Nodeenrollment lib
// This is intended for use in worker authorization; AuthorizeNode in the lib accepts the option WithState
// so that the workerId is passed through to storage and associated with a WorkerAuth record
func AttachWorkerIdToState(ctx context.Context, workerId string) (*structpb.Struct, error) {
	const op = "server.(Worker).AttachWorkerIdToState"
	if workerId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing workerId")
	}

	workerMap := &workerAuthWorkerId{WorkerId: workerId}
	s := structs.New(workerMap)
	s.TagName = "mapstructure"
	return structpb.NewStruct(s.Map())
}

// A Worker is a server that provides an address which can be used to proxy
// session connections. It can be tagged with custom tags and is used when
// authorizing and establishing a session.  It is owned by a scope.
type Worker struct {
	*store.Worker
	ApiTags               Tags   `json:"api_tags" gorm:"->"`
	ConfigTags            Tags   `json:"config_tags" gorm:"->"`
	ActiveConnectionCount uint32 `gorm:"->"`

	// inputTags is not specified to be api or config tags and is not intended
	// to be read by clients.  Since config tags and api tags are applied in
	// mutually exclusive contexts, inputTags is interpreted to be one or the
	// other based on the context in which the worker is passed.  As such
	// inputTags should only be read when performing mutations on the database.
	inputTags []*Tag `gorm:"-"`

	// This is used to pass the token back to the calling function
	ControllerGeneratedActivationToken string `gorm:"-"`

	// RemoteStorageStates is a map of storage buckets and their storage bucket credential states
	RemoteStorageStates map[string]*plugin.StorageBucketCredentialState `gorm:"-"`
}

// NewWorker returns a new Worker. Valid options are WithName, WithDescription
// WithAddress, and WithWorkerTags. All other options are ignored.  This does
// not set any of the worker reported values.
func NewWorker(scopeId string, opt ...Option) *Worker {
	opts := GetOpts(opt...)
	worker := &Worker{
		Worker: &store.Worker{
			ScopeId:           scopeId,
			Name:              opts.withName,
			Description:       opts.withDescription,
			Address:           opts.withAddress,
			ReleaseVersion:    opts.withReleaseVersion,
			OperationalState:  opts.withOperationalState,
			LocalStorageState: opts.withLocalStorageState,
		},
		inputTags: opts.withWorkerTags,
	}
	if opts.withTestUseInputTagsAsApiTags {
		worker.ApiTags = convertToTags(worker.inputTags)
	}
	return worker
}

// allocWorker will allocate a Worker
func allocWorker() Worker {
	return Worker{Worker: &store.Worker{}}
}

func (w *Worker) clone() *Worker {
	if w == nil {
		return nil
	}
	cw := proto.Clone(w.Worker)
	cWorker := &Worker{
		Worker: cw.(*store.Worker),
	}
	if w.ApiTags != nil {
		cWorker.ApiTags = w.ApiTags.clone()
	}
	if w.ConfigTags != nil {
		cWorker.ConfigTags = w.ConfigTags.clone()
	}
	if w.inputTags != nil {
		cWorker.inputTags = make([]*Tag, 0, len(w.inputTags))
		for _, t := range w.inputTags {
			cWorker.inputTags = append(cWorker.inputTags, &Tag{Key: t.Key, Value: t.Value})
		}
	}
	return cWorker
}

// CanonicalTags is the deduplicated set of tags contained on both the resource
// set over the API as well as the tags reported by the worker itself. This
// function is guaranteed to return a non-nil map.
func (w *Worker) CanonicalTags() Tags {
	return compactTags(&w.ApiTags, &w.ConfigTags)
}

// GetLastStatusTime contains the last time the worker has reported to the
// controller its connection status.  If the worker has never reported to a
// controller then nil is returned.
func (w *Worker) GetLastStatusTime() *timestamp.Timestamp {
	if w == nil || w.Worker == nil || w.Worker.GetLastStatusTime().AsTime() == timestamp.NegativeInfinityTS {
		return nil
	}
	return w.Worker.GetLastStatusTime()
}

// TableName overrides the table name used by Worker to `server_worker`
func (Worker) TableName() string {
	return "server_worker"
}
