// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"

	"github.com/fatih/structs"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/server/store"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

type (
	WorkerType        string
	OperationalState  string
	LocalStorageState string
)

const (
	UnknownWorkerType              WorkerType        = "unknown"
	KmsWorkerType                  WorkerType        = "kms"
	PkiWorkerType                  WorkerType        = "pki"
	ActiveOperationalState         OperationalState  = "active"
	ShutdownOperationalState       OperationalState  = "shutdown"
	UnknownOperationalState        OperationalState  = "unknown"
	AvailableLocalStorageState     LocalStorageState = "available"
	LowStorageLocalStorageState    LocalStorageState = "low storage"
	OutOfStorageLocalStorageState  LocalStorageState = "out of storage"
	NotConfiguredLocalStorageState LocalStorageState = "not configured"
	UnknownLocalStorageState       LocalStorageState = "unknown"
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
		OutOfStorageLocalStorageState.String(), NotConfiguredLocalStorageState.String(),
		UnknownLocalStorageState.String():
		return true
	}
	return false
}

func (t LocalStorageState) String() string {
	switch t {
	case AvailableLocalStorageState, LowStorageLocalStorageState,
		OutOfStorageLocalStorageState, NotConfiguredLocalStorageState:
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

	activeConnectionCount uint32 `gorm:"-"`
	apiTags               []*Tag `gorm:"-"`
	configTags            []*Tag `gorm:"-"`

	// inputTags is not specified to be api or config tags and is not intended
	// to be read by clients.  Since config tags and api tags are applied in
	// mutually exclusive contexts, inputTags is interpreted to be one or the
	// other based on the context in which the worker is passed.  As such
	// inputTags should only be read when performing mutations on the database.
	inputTags []*Tag `gorm:"-"`

	// This is used to pass the token back to the calling function
	ControllerGeneratedActivationToken string `gorm:"-"`
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
		worker.apiTags = worker.inputTags
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
	if w.apiTags != nil {
		cWorker.apiTags = make([]*Tag, 0, len(w.apiTags))
		for _, t := range w.apiTags {
			cWorker.apiTags = append(cWorker.apiTags, &Tag{Key: t.Key, Value: t.Value})
		}
	}
	if w.configTags != nil {
		cWorker.configTags = make([]*Tag, 0, len(w.configTags))
		for _, t := range w.configTags {
			cWorker.configTags = append(cWorker.configTags, &Tag{Key: t.Key, Value: t.Value})
		}
	}
	if w.inputTags != nil {
		cWorker.inputTags = make([]*Tag, 0, len(w.inputTags))
		for _, t := range w.inputTags {
			cWorker.inputTags = append(cWorker.inputTags, &Tag{Key: t.Key, Value: t.Value})
		}
	}
	return cWorker
}

// ActiveConnectionCount is the current number of sessions this worker is handling
// according to the controllers.
func (w *Worker) ActiveConnectionCount() uint32 {
	return w.activeConnectionCount
}

// CanonicalTags is the deduplicated set of tags contained on both the resource
// set over the API as well as the tags reported by the worker itself. This
// function is guaranteed to return a non-nil map.
func (w *Worker) CanonicalTags(opt ...Option) map[string][]string {
	dedupedTags := make(map[Tag]struct{})
	for _, t := range w.apiTags {
		dedupedTags[*t] = struct{}{}
	}
	for _, t := range w.configTags {
		dedupedTags[*t] = struct{}{}
	}
	tags := make(map[string][]string)
	for t := range dedupedTags {
		tags[t.Key] = append(tags[t.Key], t.Value)
	}
	return tags
}

// GetConfigTags returns the tags for this worker which has been set through
// the worker daemon's configuration file.
func (w *Worker) GetConfigTags() map[string][]string {
	tags := make(map[string][]string)
	for _, t := range w.configTags {
		tags[t.Key] = append(tags[t.Key], t.Value)
	}
	return tags
}

// GetApiTags returns the api tags which have been set for this worker.
func (w *Worker) GetApiTags() map[string][]string {
	tags := make(map[string][]string)
	for _, t := range w.apiTags {
		tags[t.Key] = append(tags[t.Key], t.Value)
	}
	return tags
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

// workerAggregate contains an aggregated view of the values associated with
// a single worker.
type workerAggregate struct {
	PublicId              string `gorm:"primary_key"`
	ScopeId               string
	Name                  string
	Description           string
	CreateTime            *timestamp.Timestamp
	UpdateTime            *timestamp.Timestamp
	Address               string
	Version               uint32
	Type                  string
	ReleaseVersion        string
	ApiTags               string
	ActiveConnectionCount uint32
	OperationalState      string
	LocalStorageState     string
	// Config Fields
	LastStatusTime   *timestamp.Timestamp
	WorkerConfigTags string
}

func (a *workerAggregate) toWorker(ctx context.Context) (*Worker, error) {
	const op = "server.(workerAggregate).toWorker"
	worker := &Worker{
		Worker: &store.Worker{
			PublicId:          a.PublicId,
			Name:              a.Name,
			Description:       a.Description,
			Address:           a.Address,
			CreateTime:        a.CreateTime,
			UpdateTime:        a.UpdateTime,
			ScopeId:           a.ScopeId,
			Version:           a.Version,
			LastStatusTime:    a.LastStatusTime,
			Type:              a.Type,
			ReleaseVersion:    a.ReleaseVersion,
			OperationalState:  a.OperationalState,
			LocalStorageState: a.LocalStorageState,
		},
		activeConnectionCount: a.ActiveConnectionCount,
	}
	tags, err := tagsFromAggregatedTagString(ctx, a.ApiTags)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error parsing config tag string"))
	}
	worker.apiTags = tags

	tags, err = tagsFromAggregatedTagString(ctx, a.WorkerConfigTags)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error parsing config tag string"))
	}
	worker.configTags = tags

	return worker, nil
}

// tagsForAggregatedTagString parses a deliminated string in the format returned
// by the database for the server_worker_aggregate view and returns []*Tag.
// The string is in the format of key1Yvalue1Zkey2Yvalue2Zkey3Yvalue3. Y and Z
// ares chosen for deliminators since tag keys and values are restricted from
// having capitalized letters in them.
func tagsFromAggregatedTagString(ctx context.Context, s string) ([]*Tag, error) {
	if s == "" {
		return nil, nil
	}
	const op = "server.tagsFromAggregatedTagString"
	const aggregateDelimiter = "Z"
	const pairDelimiter = "Y"
	var tags []*Tag
	for _, kv := range strings.Split(s, aggregateDelimiter) {
		res := strings.SplitN(kv, pairDelimiter, 3)
		if len(res) != 2 {
			return nil, errors.New(ctx, errors.Internal, op, "invalid aggregated tag pairs")
		}
		tags = append(tags, &Tag{
			Key:   res[0],
			Value: res[1],
		})
	}
	return tags, nil
}

func (a *workerAggregate) GetPublicId() string {
	return a.PublicId
}

func (workerAggregate) TableName() string {
	return "server_worker_aggregate"
}
