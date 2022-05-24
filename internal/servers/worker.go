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

	ReportedStatus *WorkerStatus `gorm:"-"`
	Tags           []*Tag        `gorm:"-"`
}

// NewWorker returns a new Worker. Valid options are WithName, WithDescription
// WithAddress, and WithWorkerTags. All other options are ignored.
func NewWorker(scopeId string, opt ...Option) *Worker {
	opts := getOpts(opt...)
	return &Worker{
		Worker: &store.Worker{
			ScopeId:     scopeId,
			PublicId:    opts.withPublicId,
			Name:        opts.withName,
			Description: opts.withDescription,
			Address:     opts.withAddress,
		},
		Tags: opts.withWorkerTags,
	}
}

func (w *Worker) clone() *Worker {
	if w == nil {
		return nil
	}
	tags := make([]*Tag, 0, len(w.Tags))
	for _, t := range w.Tags {
		tags = append(tags, &Tag{Key: t.Key, Value: t.Value})
	}
	cw := proto.Clone(w.Worker)
	crs := w.ReportedStatus.clone()
	return &Worker{
		Worker:         cw.(*store.Worker),
		Tags:           tags,
		ReportedStatus: crs,
	}
}

// CanonicalAddress returns the actual address boundary believes should be used
// to communicate with this worker.  This will be the worker resource's address
// unless it is not set in which case it will use address the worker provides
// in its connection status updates.  If neither is available, an empty string
// is returned.
func (w *Worker) CanonicalAddress() string {
	switch {
	case w.Address != "":
		return w.GetAddress()
	case w.ReportedStatus != nil:
		return w.ReportedStatus.GetAddress()
	default:
		return ""
	}
}

// CanonicalTags is the deduplicated set of tags contained on both the resource
// set over the API as well as the tags reported by the worker itself.
func (w *Worker) CanonicalTags() map[string][]string {
	dedupedTags := make(map[Tag]struct{})
	for _, t := range w.Tags {
		dedupedTags[*t] = struct{}{}
	}
	if w.ReportedStatus != nil {
		for _, t := range w.ReportedStatus.Tags {
			dedupedTags[*t] = struct{}{}
		}
	}
	tags := make(map[string][]string)
	for t := range dedupedTags {
		tags[t.Key] = append(tags[t.Key], t.Value)
	}
	return tags
}

// LastConnectionUpdate contains the last time the worker has reported to the
// controller its connection status.  If the worker has never reported to a
// controller then nil is returned.
func (w *Worker) LastConnectionUpdate() *timestamp.Timestamp {
	if w.ReportedStatus == nil {
		return nil
	}
	return w.ReportedStatus.GetUpdateTime()
}

// TableName overrides the table name used by Worker to `server_worker`
func (Worker) TableName() string {
	return "server_worker"
}

// workerAggregate contains an aggregated view of the values associated with
// a single worker.
type workerAggregate struct {
	PublicId               string `gorm:"primary_key"`
	ScopeId                string
	Name                   string
	Description            string
	CreateTime             *timestamp.Timestamp
	UpdateTime             *timestamp.Timestamp
	Address                string
	Version                uint32
	ApiTags                string
	WorkerStatusName       string
	WorkerStatusAddress    string
	WorkerStatusCreateTime *timestamp.Timestamp
	WorkerStatusUpdateTime *timestamp.Timestamp
	WorkerConfigTags       string
}

func (a *workerAggregate) toWorker(ctx context.Context) (*Worker, error) {
	const op = "servers.(workerAggregate).toWorker"
	workerOptions := []Option{
		WithPublicId(a.PublicId),
		WithName(a.Name),
		WithDescription(a.Description),
		WithAddress(a.Address),
	}
	tags, err := tagsFromAggregatedTagString(ctx, a.ApiTags)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error parsing config tag string"))
	}
	if len(tags) > 0 {
		workerOptions = append(workerOptions, WithWorkerTags(tags...))
	}
	worker := NewWorker(a.ScopeId, workerOptions...)
	worker.CreateTime = a.CreateTime
	worker.UpdateTime = a.UpdateTime
	worker.Version = a.Version

	if a.WorkerStatusCreateTime == nil {
		return worker, nil
	}
	statusOptions := []Option{
		WithName(a.WorkerStatusName),
		WithAddress(a.WorkerStatusAddress),
	}
	tags, err = tagsFromAggregatedTagString(ctx, a.WorkerConfigTags)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error parsing config tag string"))
	}
	if len(tags) > 0 {
		statusOptions = append(statusOptions, WithWorkerTags(tags...))
	}
	cfg := NewWorkerStatus(a.PublicId, statusOptions...)
	cfg.CreateTime = a.WorkerStatusCreateTime
	cfg.UpdateTime = a.WorkerStatusUpdateTime

	worker.ReportedStatus = cfg
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
