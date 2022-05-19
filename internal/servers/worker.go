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

	Config *WorkerConfig `gorm:"-"`
	Tags   []*Tag        `gorm:"-"`
}

// A Tag is a custom key/value pair which can be attached to a Worker.
// Multiple Tags may contain the same key and different values in which
// case both key/value pairs are valid.
type Tag struct {
	Key   string
	Value string
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
	tags := make([]*Tag, 0, len(w.Tags))
	for _, t := range w.Tags {
		tags = append(tags, &Tag{Key: t.Key, Value: t.Value})
	}
	cw := proto.Clone(w.Worker)
	return &Worker{
		Worker: cw.(*store.Worker),
		Tags:   tags,
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
	case w.Config != nil:
		return w.Config.GetAddress()
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
	if w.Config != nil {
		for _, t := range w.Config.Tags {
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
	if w.Config == nil {
		return nil
	}
	return w.Config.GetUpdateTime()
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
	WorkerConfigName       string
	WorkerConfigAddress    string
	WorkerConfigCreateTime *timestamp.Timestamp
	WorkerConfigUpdateTime *timestamp.Timestamp
	WorkerConfigTags       string
}

func (a *workerAggregate) toWorker(ctx context.Context) (*Worker, error) {
	const op = "servers.(workerAggregate).toWorker"
	worker := NewWorker(a.ScopeId,
		WithPublicId(a.PublicId),
		WithName(a.Name),
		WithDescription(a.Description),
		WithAddress(a.Address))
	worker.CreateTime = a.CreateTime
	worker.UpdateTime = a.UpdateTime
	worker.Version = a.Version

	if a.WorkerConfigCreateTime == nil {
		return worker, nil
	}
	configOptions := []Option{
		WithName(a.WorkerConfigName),
		WithAddress(a.WorkerConfigAddress),
	}
	tags, err := tagsFromAggregatedTagString(ctx, a.WorkerConfigTags)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error parsing config tag string"))
	}
	if len(tags) > 0 {
		configOptions = append(configOptions, WithWorkerTags(tags...))
	}
	cfg := NewWorkerConfig(a.PublicId, configOptions...)
	cfg.CreateTime = a.WorkerConfigCreateTime
	cfg.UpdateTime = a.WorkerConfigUpdateTime

	worker.Config = cfg
	return worker, nil
}

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
