package common

import (
	stderrors "errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/server"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/go-bexpr"
	"github.com/mitchellh/pointerstructure"
	"google.golang.org/grpc/codes"
)

// WorkerList is a helper type to make the selection of workers clearer and more declarative.
type WorkerList []*server.Worker

// addresses converts the slice of workers to a slice of their addresses
func (w WorkerList) Addresses() []string {
	ret := make([]string, 0, len(w))
	for _, worker := range w {
		ret = append(ret, worker.GetAddress())
	}
	return ret
}

// PublicIds converts the slice of workers to a slice of public ids of those
// workers.
func (w WorkerList) PublicIds() []string {
	ret := make([]string, 0, len(w))
	for _, worker := range w {
		ret = append(ret, worker.GetPublicId())
	}
	return ret
}

// workerInfos converts the slice of workers to a slice of their workerInfo protos
func (w WorkerList) WorkerInfos() []*pb.WorkerInfo {
	ret := make([]*pb.WorkerInfo, 0, len(w))
	for _, worker := range w {
		ret = append(ret, &pb.WorkerInfo{Address: worker.GetAddress()})
	}
	return ret
}

// filtered returns a new workerList where all elements contained in it are the
// ones which from the original workerList that pass the evaluator's evaluation.
func (w WorkerList) Filtered(eval *bexpr.Evaluator) (WorkerList, error) {
	var ret []*server.Worker
	for _, worker := range w {
		filterInput := map[string]any{
			"name": worker.GetName(),
			"tags": worker.CanonicalTags(),
		}
		ok, err := eval.Evaluate(filterInput)
		if err != nil && !stderrors.Is(err, pointerstructure.ErrNotFound) {
			return nil, handlers.ApiErrorWithCodeAndMessage(
				codes.FailedPrecondition,
				fmt.Sprintf("Worker filter expression evaluation resulted in error: %s", err))
		}
		if ok {
			ret = append(ret, worker)
		}
	}
	return ret, nil
}
