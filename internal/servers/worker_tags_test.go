package servers

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/servers/store"
	"github.com/stretchr/testify/assert"
)

func TestWorkerTags_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	worker := TestKmsWorker(t, conn, wrapper)

	tests := []struct {
		name          string
		want          *store.WorkerTag
		wantCreateErr bool
	}{
		{
			name: "success api source",
			want: &store.WorkerTag{
				WorkerId: worker.GetPublicId(),
				Key:      "key",
				Value:    "value",
				Source:   ApiTagSource.String(),
			},
		},
		{
			name: "success config source",
			want: &store.WorkerTag{
				WorkerId: worker.GetPublicId(),
				Key:      "key",
				Value:    "value",
				Source:   ConfigurationTagSource.String(),
			},
		},
		{
			name: "unknown source",
			want: &store.WorkerTag{
				WorkerId: worker.GetPublicId(),
				Key:      "key",
				Value:    "value",
				Source:   "unknown",
			},
			wantCreateErr: true,
		},
		{
			name: "no source",
			want: &store.WorkerTag{
				WorkerId: worker.GetPublicId(),
				Key:      "key",
				Value:    "value",
			},
			wantCreateErr: true,
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
			wantCreateErr: true,
		},
		{
			name: "missing value",
			want: &store.WorkerTag{
				WorkerId: worker.GetPublicId(),
				Key:      "key",
			},
			wantCreateErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := rw.Create(context.Background(), tt.want)
			if tt.wantCreateErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
