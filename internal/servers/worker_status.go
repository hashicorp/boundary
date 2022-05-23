package servers

import (
	"github.com/hashicorp/boundary/internal/servers/store"
	"google.golang.org/protobuf/proto"
)

// A WorkerStatus is a container for the fields that a worker reports to the
// controller about itself in its status updates.  While this may include a
// Name, this is different from the Worker's name in that the Worker's name is
// the name of the Worker resource in boundary where the name in the
// WorkerStatus is the name the worker has reported about itself.
type WorkerStatus struct {
	*store.WorkerStatus
	Tags []*Tag `gorm:"-"`
}

// NewWorkerStatus returns a new WorkerStatus. Valid options are WithName,
// WithAddress, and WithWorkerTags. All other options are ignored.
func NewWorkerStatus(workerId string, opt ...Option) *WorkerStatus {
	opts := getOpts(opt...)
	return &WorkerStatus{
		WorkerStatus: &store.WorkerStatus{
			WorkerId: workerId,
			Name:     opts.withName,
			Address:  opts.withAddress,
		},
		Tags: opts.withWorkerTags,
	}
}

func (w *WorkerStatus) clone() *WorkerStatus {
	tags := make([]*Tag, 0, len(w.Tags))
	for _, t := range w.Tags {
		tags = append(tags, &Tag{Key: t.Key, Value: t.Value})
	}
	cw := proto.Clone(w.WorkerStatus)
	return &WorkerStatus{
		WorkerStatus: cw.(*store.WorkerStatus),
		Tags:         tags,
	}
}

// TableName overrides the table name used by WorkerStatus to `server_worker_status`
func (WorkerStatus) TableName() string {
	return "server_worker_status"
}
