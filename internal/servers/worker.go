package servers

import (
	"github.com/hashicorp/boundary/internal/db/timestamp"
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

func (w *Worker) CanonicalAddress() string {
	switch {
	case w.Address != "":
		return w.GetAddress()
	default:
		return w.Config.GetAddress()
	}
}

func (w *Worker) LastConnectionUpdate() *timestamp.Timestamp {
	return w.Config.GetUpdateTime()
}

// TableName overrides the table name used by Worker to `server_worker`
func (Worker) TableName() string {
	return "server_worker"
}

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
}

func (a *workerAggregate) toWorker() *Worker {
	worker := NewWorker(a.ScopeId,
		WithPublicId(a.PublicId),
		WithName(a.Name),
		WithDescription(a.Description),
		WithAddress(a.Address))
	worker.CreateTime = a.CreateTime
	worker.UpdateTime = a.UpdateTime
	worker.Version = a.Version

	cfg := NewWorkerConfig(a.PublicId,
		WithName(a.WorkerConfigName),
		WithAddress(a.WorkerConfigAddress))
	cfg.CreateTime = a.WorkerConfigCreateTime
	cfg.UpdateTime = a.WorkerConfigUpdateTime
	worker.Config = cfg
	return worker
}

func (a *workerAggregate) GetPublicId() string {
	return a.PublicId
}

func (workerAggregate) TableName() string {
	return "server_worker_aggregate"
}
