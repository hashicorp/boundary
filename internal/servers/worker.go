package servers

import (
	"context"
	"strings"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/servers/store"
	"google.golang.org/protobuf/proto"
)

// A Worker is a server that provides an address which can be used to proxy
// session connections. It can be tagged with custom tags and is used when
// authorizing and establishing a session.  It is owned by a scope.
type Worker struct {
	*store.Worker

	apiTags    []*Tag `gorm:"-"`
	configTags []*Tag `gorm:"-"`
}

// NewWorker returns a new Worker. Valid options are WithName, WithDescription
// WithAddress, and WithWorkerTags. All other options are ignored.  This does
// not set any of the worker reported values.
func NewWorker(scopeId string, opt ...Option) *Worker {
	opts := getOpts(opt...)
	return &Worker{
		Worker: &store.Worker{
			ScopeId:     scopeId,
			Name:        opts.withName,
			Description: opts.withDescription,
			Address:     opts.withAddress,
		},
		apiTags: opts.withWorkerTags,
	}
}

// NewWorkerForStatus returns a new Worker usable for status updates.
// Valid options are WithName WithAddress, and WithWorkerTags, all of which
// are assigned to the worker reported variations of these fields.
// All other options are ignored.
func NewWorkerForStatus(scopeId string, opt ...Option) *Worker {
	opts := getOpts(opt...)
	return &Worker{
		Worker: &store.Worker{
			ScopeId:               scopeId,
			WorkerReportedName:    opts.withName,
			WorkerReportedAddress: opts.withAddress,
		},
		configTags: opts.withWorkerTags,
	}
}

func (w *Worker) clone() *Worker {
	if w == nil {
		return nil
	}
	apiTags := make([]*Tag, 0, len(w.apiTags))
	for _, t := range w.apiTags {
		apiTags = append(apiTags, &Tag{Key: t.Key, Value: t.Value})
	}
	configTags := make([]*Tag, 0, len(w.apiTags))
	for _, t := range w.configTags {
		configTags = append(configTags, &Tag{Key: t.Key, Value: t.Value})
	}
	cw := proto.Clone(w.Worker)
	return &Worker{
		Worker:     cw.(*store.Worker),
		apiTags:    apiTags,
		configTags: configTags,
	}
}

// CanonicalAddress returns the actual address boundary believes should be used
// to communicate with this worker.  This will be the worker resource's address
// unless it is not set in which case it will use address the worker provides
// in its connection status updates.  If neither is available, an empty string
// is returned.
func (w *Worker) CanonicalAddress() string {
	if w.GetAddress() != "" {
		return w.GetAddress()
	}
	return w.GetWorkerReportedAddress()
}

// CanonicalTags is the deduplicated set of tags contained on both the resource
// set over the API as well as the tags reported by the worker itself.
func (w *Worker) CanonicalTags() map[string][]string {
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

func (w *Worker) GetApiTags() map[string][]string {
	tags := make(map[string][]string)
	for _, t := range w.apiTags {
		tags[t.Key] = append(tags[t.Key], t.Value)
	}
	return tags
}

func (w *Worker) GetConfigTags() map[string][]string {
	tags := make(map[string][]string)
	for _, t := range w.configTags {
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
	ApiTags               string
	WorkerReportedName    string
	WorkerReportedAddress string
	LastStatusTime        *timestamp.Timestamp
	WorkerConfigTags      string
}

func (a *workerAggregate) toWorker(ctx context.Context) (*Worker, error) {
	const op = "servers.(workerAggregate).toWorker"
	worker := &Worker{
		Worker: &store.Worker{
			PublicId:              a.PublicId,
			Name:                  a.Name,
			Description:           a.Description,
			Address:               a.Address,
			CreateTime:            a.CreateTime,
			UpdateTime:            a.UpdateTime,
			ScopeId:               a.ScopeId,
			Version:               a.Version,
			WorkerReportedAddress: a.WorkerReportedAddress,
			WorkerReportedName:    a.WorkerReportedName,
			LastStatusTime:        a.LastStatusTime,
		},
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
	const op = "servers.tagsFromAggregatedTagString"
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
