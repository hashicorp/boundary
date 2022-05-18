package servers

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/servers/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkerTags_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	workerPublicid, err := newWorkerId(context.Background())
	require.NoError(t, err)
	worker := NewWorker(scope.Global.String(), WithPublicId(workerPublicid))

	tests := []struct {
		name          string
		want          *store.WorkerTag
		wantCreateErr bool
	}{
		{
			name: "success",
			want: &store.WorkerTag{
				WorkerId: worker.GetPublicId(),
				Key:      "key",
				Value:    "value",
			},
		},
		{
			name: "bad worker id",
			want: &store.WorkerTag{
				WorkerId: "w_badworkeridthatdoesntexist",
				Key:      "key",
				Value:    "value",
			},
			wantCreateErr: true,
		},
		{
			name: "missing worker id",
			want: &store.WorkerTag{
				Key:   "key",
				Value: "value",
			},
			wantCreateErr: true,
		},
		{
			name: "missing key",
			want: &store.WorkerTag{
				WorkerId: worker.GetPublicId(),
				Value:    "value",
			},
		},
		{
			name: "missing value",
			want: &store.WorkerTag{
				WorkerId: worker.GetPublicId(),
				Key:      "key",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := rw.Create(context.Background(), tt.want)
			if tt.wantCreateErr {
				assert.Error(t, err)
			}
		})
	}
}
