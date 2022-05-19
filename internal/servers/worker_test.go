package servers

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestWorkerCanonicalAddress(t *testing.T) {
	worker := NewWorker(scope.Global.String())
	worker.Config = NewWorkerConfig("foo", WithAddress("config"))
	assert.Equal(t, "config", worker.CanonicalAddress())
	worker.Address = "worker"
	assert.Equal(t, "worker", worker.CanonicalAddress())
}

func TestWorkerCanonicalTags(t *testing.T) {
	w := NewWorker(scope.Global.String(),
		WithWorkerTags(
			&Tag{Key: "key", Value: "apis unique"},
			&Tag{Key: "key", Value: "shared"},
			&Tag{Key: "key2", Value: "apis key2 unique"},
		))
	w.Config = NewWorkerConfig("",
		WithWorkerTags(
			&Tag{Key: "key", Value: "configs unique"},
			&Tag{Key: "key", Value: "shared"},
			&Tag{Key: "key3", Value: "configs key3 unique"},
		))

	got := w.CanonicalTags()
	assert.Len(t, got, 3, "2 keys expected, 'key' and 'key2'")
	assert.ElementsMatch(t, got["key"], []string{"shared", "apis unique", "configs unique"})
	assert.ElementsMatch(t, got["key2"], []string{"apis key2 unique"})
	assert.ElementsMatch(t, got["key3"], []string{"configs key3 unique"})
}

func TestWorkerAggregate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	ctx := context.Background()

	getAggWorker := func(id string) *Worker {
		agg := &workerAggregate{PublicId: id}
		require.NoError(t, rw.LookupById(ctx, agg))
		got, err := agg.toWorker(ctx)
		assert.NoError(t, err)
		return got
	}

	// Worker without a config
	{
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		require.NoError(t, rw.Create(ctx,
			NewWorker(scope.Global.String(),
				WithPublicId(id),
				WithName(id),
				WithAddress("address"))))

		got := getAggWorker(id)
		assert.Equal(t, id, got.GetPublicId())
		assert.Equal(t, scope.Global.String(), got.GetScopeId())
		assert.Equal(t, id, got.GetName())
		assert.Equal(t, "address", got.GetAddress())
		assert.Equal(t, uint32(1), got.GetVersion())
		assert.Nil(t, got.Config)
		assert.Empty(t, got.CanonicalTags())
	}

	// Worker with config
	{
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		require.NoError(t, rw.Create(ctx,
			NewWorker(scope.Global.String(), WithPublicId(id))))
		require.NoError(t, rw.Create(ctx,
			NewWorkerConfig(id,
				WithAddress("address"),
				WithName(id))))

		got := getAggWorker(id)
		assert.Equal(t, id, got.GetPublicId())
		assert.Equal(t, uint32(1), got.GetVersion())
		assert.NotNil(t, got.Config)
		assert.Equal(t, id, got.Config.GetWorkerId())
		assert.Equal(t, id, got.Config.GetName())
		assert.NotNil(t, got.Config.CreateTime)
		assert.NotNil(t, got.Config.UpdateTime)
		assert.Equal(t, "address", got.Config.GetAddress())
	}

	// Worker with a config tag
	{
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		require.NoError(t, rw.Create(ctx,
			NewWorker(scope.Global.String(), WithPublicId(id))))
		require.NoError(t, rw.Create(ctx,
			NewWorkerConfig(id, WithAddress("address"))))
		require.NoError(t, rw.Create(ctx,
			&store.WorkerTag{
				WorkerId: id,
				Key:      "key",
				Value:    "val",
			}))

		got := getAggWorker(id)
		assert.Equal(t, id, got.GetPublicId())
		assert.Equal(t, uint32(1), got.GetVersion())
		assert.NotNil(t, got.Config)
		assert.Empty(t, got.Tags)
		assert.Equal(t, got.Config.Tags, []*Tag{{Key: "key", Value: "val"}})
	}

	// Worker with many config tag
	{
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		require.NoError(t, rw.Create(ctx,
			NewWorker(scope.Global.String(), WithPublicId(id))))
		require.NoError(t, rw.Create(ctx,
			NewWorkerConfig(id, WithAddress("address"))))
		require.NoError(t, rw.Create(ctx, &store.WorkerTag{
			WorkerId: id,
			Key:      "key",
			Value:    "val",
		}))
		require.NoError(t, rw.Create(ctx, &store.WorkerTag{
			WorkerId: id,
			Key:      "key",
			Value:    "val2",
		}))
		require.NoError(t, rw.Create(ctx, &store.WorkerTag{
			WorkerId: id,
			Key:      "key2",
			Value:    "val2",
		}))

		got := getAggWorker(id)
		require.NotNil(t, got.Config)
		assert.Empty(t, got.Tags)
		assert.ElementsMatch(t, got.Config.Tags, []*Tag{
			{Key: "key", Value: "val"},
			{Key: "key", Value: "val2"},
			{Key: "key2", Value: "val2"},
		})
	}
}

func TestWorker_New(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	type args struct {
		scopeId string
		opts    []Option
	}

	tests := []struct {
		name          string
		args          args
		want          *Worker
		wantCreateErr bool
	}{
		{
			name: "missing-scope-id",
			args: args{},
			want: &Worker{
				Worker: &store.Worker{},
			},
			wantCreateErr: true,
		},
		{
			name: "global-scope-id",
			args: args{
				scopeId: scope.Global.String(),
			},
			want: &Worker{
				Worker: &store.Worker{
					ScopeId: scope.Global.String(),
				},
			},
		},
		{
			name: "org-scope-id",
			args: args{
				scopeId: org.GetPublicId(),
			},
			want: &Worker{
				Worker: &store.Worker{
					ScopeId: org.GetPublicId(),
				},
			},
			wantCreateErr: true,
		},
		{
			name: "project-scope-id",
			args: args{
				scopeId: prj.GetPublicId(),
			},
			want: &Worker{
				Worker: &store.Worker{
					ScopeId: prj.GetPublicId(),
				},
			},
			wantCreateErr: true,
		},
		{
			name: "with public id",
			args: args{
				scopeId: scope.Global.String(),
				opts: []Option{
					WithPublicId("w_test_public_id"),
				},
			},
			want: &Worker{
				Worker: &store.Worker{
					PublicId: "w_test_public_id",
					ScopeId:  scope.Global.String(),
				},
			},
		},
		{
			name: "with name",
			args: args{
				scopeId: scope.Global.String(),
				opts: []Option{
					WithName("foo"),
				},
			},
			want: &Worker{
				Worker: &store.Worker{
					ScopeId: scope.Global.String(),
					Name:    "foo",
				},
			},
		},
		{
			name: "with description",
			args: args{
				scopeId: scope.Global.String(),
				opts: []Option{
					WithDescription("foo"),
				},
			},
			want: &Worker{
				Worker: &store.Worker{
					ScopeId:     scope.Global.String(),
					Description: "foo",
				},
			},
		},
		{
			name: "with address",
			args: args{
				scopeId: scope.Global.String(),
				opts: []Option{
					WithAddress("foo"),
				},
			},
			want: &Worker{
				Worker: &store.Worker{
					ScopeId: scope.Global.String(),
					Address: "foo",
				},
			},
		},
		{
			name: "with Tags",
			args: args{
				scopeId: scope.Global.String(),
				opts: []Option{
					WithWorkerTags(&Tag{
						Key:   "key",
						Value: "val",
					}),
				},
			},
			want: &Worker{
				Worker: &store.Worker{
					ScopeId: scope.Global.String(),
				},
				Tags: []*Tag{
					{
						Key:   "key",
						Value: "val",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := NewWorker(tt.args.scopeId, tt.args.opts...)
			assert.Empty(cmp.Diff(tt.want, got.clone(), protocmp.Transform()))

			id, err := newWorkerId(context.Background())
			assert.NoError(err)

			tt.want.PublicId = id
			got.PublicId = id

			err2 := rw.Create(context.Background(), got)
			if tt.wantCreateErr {
				assert.Error(err2)
			} else {
				assert.NoError(err2)
				assert.Equal(uint32(1), got.Version)
			}
		})
	}
}
