package servers

import (
	"github.com/hashicorp/boundary/internal/servers/store"
	"google.golang.org/protobuf/proto"
)

// A WorkerConfig is a container for the fields that a worker reports to the
// controller about itself.  While the config may include a Name, this is
// different from the Worker's name in that the Worker's name is the name of
// the Worker resource in boundary where the name in the WorkerConfig is the
// name the worker has reported about itself.
type WorkerConfig struct {
	*store.WorkerConfig
	Tags []*Tag `gorm:"-"`
}

// NewWorkerConfig returns a new WorkerConfig. Valid options are WithName,
// WithAddress, and WithWorkerTags. All other options are ignored.
func NewWorkerConfig(workerId string, opt ...Option) *WorkerConfig {
	opts := getOpts(opt...)
	return &WorkerConfig{
		WorkerConfig: &store.WorkerConfig{
			WorkerId: workerId,
			Name:     opts.withName,
			Address:  opts.withAddress,
		},
		Tags: opts.withWorkerTags,
	}
}

func (w *WorkerConfig) clone() *WorkerConfig {
	tags := make([]*Tag, 0, len(w.Tags))
	for _, t := range w.Tags {
		tags = append(tags, &Tag{Key: t.Key, Value: t.Value})
	}
	cw := proto.Clone(w.WorkerConfig)
	return &WorkerConfig{
		WorkerConfig: cw.(*store.WorkerConfig),
		Tags:         tags,
	}
}

// TableName overrides the table name used by WorkerConfig to `server_worker_config`
func (WorkerConfig) TableName() string {
	return "server_worker_config"
}
