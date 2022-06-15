package targets

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/go-bexpr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkerList_Addresses(t *testing.T) {
	addresses := []string{
		"test1",
		"test2",
		"test3",
		"test4",
	}
	var workerInfos []*pb.WorkerInfo
	var tested workerList
	for _, a := range addresses {
		workerInfos = append(workerInfos, &pb.WorkerInfo{Address: a})
		tested = append(tested, servers.NewWorker(scope.Global.String(),
			servers.WithName(a),
			servers.WithAddress(a)))
	}
	assert.Equal(t, addresses, tested.addresses())
	assert.Equal(t, workerInfos, tested.workerInfos())
}

func TestWorkerList_Filter(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	var workers []*servers.Worker
	for i := 0; i < 5; i++ {
		switch {
		case i%2 == 0:
			workers = append(workers, servers.TestKmsWorker(t, conn, wrapper,
				servers.WithName(fmt.Sprintf("test_worker_%d", i)),
				servers.WithWorkerTags(&servers.Tag{
					Key:   fmt.Sprintf("key%d", i),
					Value: fmt.Sprintf("value%d", i),
				})))
		default:
			workers = append(workers, servers.TestPkiWorker(t, conn, wrapper,
				servers.WithName(fmt.Sprintf("test_worker_%d", i)),
				servers.WithWorkerTags(&servers.Tag{
					Key:   "key",
					Value: "configvalue",
				})))
		}
	}

	{
		ev, err := bexpr.CreateEvaluator(`"/name" matches "test_worker_[13]" and "configvalue2" in "/tags/key"`)
		require.NoError(t, err)
		got, err := workerList(workers).filtered(ev)
		require.NoError(t, err)
		assert.Len(t, got, 0)
	}
	{
		ev, err := bexpr.CreateEvaluator(`"/name" matches "test_worker_[12]" and "configvalue" in "/tags/key"`)
		require.NoError(t, err)
		got, err := workerList(workers).filtered(ev)
		require.NoError(t, err)
		assert.Len(t, got, 1)
	}
	{
		ev, err := bexpr.CreateEvaluator(`"configvalue" in "/tags/key"`)
		require.NoError(t, err)
		got, err := workerList(workers).filtered(ev)
		require.NoError(t, err)
		assert.Len(t, got, 2)
	}
}
