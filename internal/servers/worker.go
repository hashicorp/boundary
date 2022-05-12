package servers

import (
	"github.com/hashicorp/boundary/internal/servers/store"
	"google.golang.org/protobuf/proto"
)

// A Worker is a server with an address that connects to a controller.
// It can be tagged with custom tags and is used when authorizing and
// establishing a session.  It is owned by a scope.
type Worker struct {
	*store.Worker
	Tags []*Tag `gorm:"-"`
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

// TableName overrides the table name used by Worker to `server_worker`
func (Worker) TableName() string {
	return "server_worker"
}
