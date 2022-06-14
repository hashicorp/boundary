package servers

import (
	"context"
	"strings"
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
	ctx := context.Background()
	worker, err := NewWorkerForStatus(ctx, scope.Global.String(), WithAddress("status"))
	assert.NoError(t, err)
	assert.Equal(t, "status", worker.CanonicalAddress())
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
	w.configTags = []*Tag{
		{Key: "key", Value: "configs unique"},
		{Key: "key", Value: "shared"},
		{Key: "key3", Value: "configs key3 unique"},
	}

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

	// Worker without a status
	{
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		w := NewWorker(scope.Global.String(),
			WithName(id),
			WithAddress("address"))
		w.PublicId = id
		require.NoError(t, rw.Create(ctx, w))

		got := getAggWorker(id)
		assert.Equal(t, id, got.GetPublicId())
		assert.Equal(t, scope.Global.String(), got.GetScopeId())
		assert.Equal(t, id, got.GetName())
		assert.Equal(t, "address", got.GetAddress())
		assert.Equal(t, uint32(1), got.GetVersion())
		assert.Nil(t, got.GetLastStatusTime())
		assert.Empty(t, got.CanonicalTags())
	}

	// Worker with status
	{
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		w, err := NewWorkerForStatus(ctx, scope.Global.String(),
			WithAddress("address"),
			WithName(strings.ToLower(id)))
		require.NoError(t, err)
		w.PublicId = id
		require.NoError(t, rw.Create(ctx, w))

		got := getAggWorker(id)
		assert.Equal(t, id, got.GetPublicId())
		assert.Equal(t, uint32(1), got.GetVersion())
		assert.NotNil(t, got.GetLastStatusTime())
		assert.Equal(t, strings.ToLower(id), got.GetWorkerReportedName())
		assert.Equal(t, "address", got.GetWorkerReportedAddress())
	}

	// Worker with a config tag
	{
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		ws, err := NewWorkerForStatus(ctx, scope.Global.String(),
			WithAddress("address"),
			WithName(strings.ToLower(id)))
		require.NoError(t, err)
		ws.PublicId = id
		require.NoError(t, rw.Create(ctx, ws))
		require.NoError(t, rw.Create(ctx,
			&store.WorkerTag{
				WorkerId: id,
				Key:      "key",
				Value:    "val",
				Source:   ConfigurationTagSource.String(),
			}))

		got := getAggWorker(id)
		assert.Equal(t, id, got.GetPublicId())
		assert.Equal(t, uint32(1), got.GetVersion())
		assert.NotNil(t, got.GetLastStatusTime())
		assert.Empty(t, got.apiTags)
		assert.Equal(t, got.configTags, []*Tag{{Key: "key", Value: "val"}})
	}

	// Worker with many config tag
	{
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		ws, err := NewWorkerForStatus(ctx, scope.Global.String(),
			WithAddress("address"),
			WithName(strings.ToLower(id)))
		require.NoError(t, err)
		ws.PublicId = id
		require.NoError(t, rw.Create(ctx, ws))
		require.NoError(t, rw.Create(ctx, &store.WorkerTag{
			WorkerId: id,
			Key:      "key",
			Value:    "val",
			Source:   ConfigurationTagSource.String(),
		}))
		require.NoError(t, rw.Create(ctx, &store.WorkerTag{
			WorkerId: id,
			Key:      "key",
			Value:    "val2",
			Source:   ConfigurationTagSource.String(),
		}))
		require.NoError(t, rw.Create(ctx, &store.WorkerTag{
			WorkerId: id,
			Key:      "key2",
			Value:    "val2",
			Source:   ConfigurationTagSource.String(),
		}))

		got := getAggWorker(id)
		require.NotNil(t, got.GetLastStatusTime())
		assert.Empty(t, got.apiTags)
		assert.ElementsMatch(t, got.configTags, []*Tag{
			{Key: "key", Value: "val"},
			{Key: "key", Value: "val2"},
			{Key: "key2", Value: "val2"},
		})
	}

	// Worker with an api tag
	{
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		ws, err := NewWorkerForStatus(ctx, scope.Global.String(),
			WithAddress("address"),
			WithName(strings.ToLower(id)))
		require.NoError(t, err)
		ws.PublicId = id
		require.NoError(t, rw.Create(ctx, ws))
		require.NoError(t, rw.Create(ctx,
			&store.WorkerTag{
				WorkerId: id,
				Key:      "key",
				Value:    "val",
				Source:   ApiTagSource.String(),
			}))

		got := getAggWorker(id)
		assert.Equal(t, id, got.GetPublicId())
		assert.Equal(t, uint32(1), got.GetVersion())
		assert.NotNil(t, got.GetLastStatusTime())
		assert.Empty(t, got.GetConfigTags())
		assert.Equal(t, got.apiTags, []*Tag{{Key: "key", Value: "val"}})
	}

	// Worker with mix of tag sources
	{
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		ws, err := NewWorkerForStatus(ctx, scope.Global.String(),
			WithAddress("address"),
			WithName(strings.ToLower(id)))
		require.NoError(t, err)
		ws.PublicId = id
		require.NoError(t, rw.Create(ctx, ws))
		require.NoError(t, rw.Create(ctx, &store.WorkerTag{
			WorkerId: id,
			Key:      "key",
			Value:    "val",
			Source:   ConfigurationTagSource.String(),
		}))
		require.NoError(t, rw.Create(ctx, &store.WorkerTag{
			WorkerId: id,
			Key:      "key",
			Value:    "val2",
			Source:   ApiTagSource.String(),
		}))
		require.NoError(t, rw.Create(ctx, &store.WorkerTag{
			WorkerId: id,
			Key:      "key2",
			Value:    "val2",
			Source:   ApiTagSource.String(),
		}))

		got := getAggWorker(id)
		require.NotNil(t, got.GetLastStatusTime())
		assert.ElementsMatch(t, got.apiTags, []*Tag{
			{Key: "key", Value: "val2"},
			{Key: "key2", Value: "val2"},
		})
		assert.ElementsMatch(t, got.configTags, []*Tag{
			{Key: "key", Value: "val"},
		})
	}
}

func TestWorker_Update(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	ctx := context.Background()

	newId := func() string {
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		return id
	}

	cases := []struct {
		name            string
		initial         Worker
		update          Worker
		mask            []string
		nullMask        []string
		assert          func(t *testing.T, init, up *Worker)
		wantUpdateError bool
	}{
		{
			name: "base update with base",
			initial: Worker{
				Worker: &store.Worker{
					ScopeId:     scope.Global.String(),
					PublicId:    newId(),
					Description: "base update with base",
				},
			},
			update: Worker{
				Worker: &store.Worker{
					Description: "base update with base updated",
				},
			},
			mask: []string{"Description"},
			assert: func(t *testing.T, init, up *Worker) {
				t.Helper()
				assert.Equal(t, "base update with base updated", up.Description)
				assert.Greater(t, up.GetUpdateTime().AsTime(), up.GetCreateTime().AsTime())
				assert.Equal(t, uint32(2), up.Version)
				assert.Nil(t, up.GetLastStatusTime())
			},
		},
		{
			name: "base update with worker reported address and name",
			initial: Worker{
				Worker: &store.Worker{
					ScopeId:     scope.Global.String(),
					PublicId:    newId(),
					Description: "base update with status",
				},
			},
			update: Worker{
				Worker: &store.Worker{
					WorkerReportedName:    "base update with worker reported address and name",
					WorkerReportedAddress: "base update with worker reported address and name",
				},
			},
			mask: []string{"WorkerReportedAddress", "WorkerReportedName"},
			assert: func(t *testing.T, init, up *Worker) {
				t.Helper()
				assert.Equal(t, "base update with worker reported address and name", up.WorkerReportedAddress)
				assert.Equal(t, "base update with worker reported address and name", up.WorkerReportedName)
				assert.Equal(t, uint32(1), up.Version)
				assert.NotNil(t, up.GetLastStatusTime())
				assert.Greater(t, up.GetUpdateTime().AsTime(), up.GetCreateTime().AsTime())
				assert.Equal(t, up.GetLastStatusTime().AsTime(), up.GetUpdateTime().AsTime())
			},
		},
		{
			name: "base update with worker reported address and keyId",
			initial: Worker{
				Worker: &store.Worker{
					ScopeId:     scope.Global.String(),
					PublicId:    newId(),
					Description: "base update with status",
				},
			},
			update: Worker{
				Worker: &store.Worker{
					KeyId:                 "base update with worker reported address and keyId",
					WorkerReportedAddress: "base update with worker reported address and keyId",
				},
			},
			mask: []string{"WorkerReportedAddress", "KeyId"},
			assert: func(t *testing.T, init, up *Worker) {
				t.Helper()
				assert.Equal(t, "base update with worker reported address and keyId", up.WorkerReportedAddress)
				assert.Equal(t, "base update with worker reported address and keyId", up.KeyId)
				assert.Equal(t, uint32(1), up.Version)
				assert.NotNil(t, up.GetLastStatusTime())
				assert.Greater(t, up.GetUpdateTime().AsTime(), up.GetCreateTime().AsTime())
				assert.Equal(t, up.GetLastStatusTime().AsTime(), up.GetUpdateTime().AsTime())
			},
		},
		{
			name: "base update with worker reported address",
			initial: Worker{
				Worker: &store.Worker{
					ScopeId:     scope.Global.String(),
					PublicId:    newId(),
					Description: "base update with status",
				},
			},
			update: Worker{
				Worker: &store.Worker{
					WorkerReportedAddress: "base update with worker reported address",
				},
			},
			mask:            []string{"WorkerReportedAddress"},
			wantUpdateError: true,
		},
		{
			// If any status fields are set then worker reported address must
			// be set.
			name: "base update with worker reported name",
			initial: Worker{
				Worker: &store.Worker{
					ScopeId:     scope.Global.String(),
					PublicId:    newId(),
					Description: "base update with status",
				},
			},
			update: Worker{
				Worker: &store.Worker{
					WorkerReportedName: "base update with worker reported name",
				},
			},
			mask:            []string{"WorkerReportedName"},
			wantUpdateError: true,
		},
		{
			// If any status fields are set then worker reported address must
			// be set.
			name: "base update with worker reported keyId",
			initial: Worker{
				Worker: &store.Worker{
					ScopeId:     scope.Global.String(),
					PublicId:    newId(),
					Description: "base update with status",
				},
			},
			update: Worker{
				Worker: &store.Worker{
					KeyId: "base update with worker reported keyId",
				},
			},
			mask:            []string{"WorkerReportedKeyId"},
			wantUpdateError: true,
		},
		{
			name: "base update with worker reported fields",
			initial: Worker{
				Worker: &store.Worker{
					ScopeId:     scope.Global.String(),
					PublicId:    newId(),
					Description: "base update with status",
				},
			},
			update: Worker{
				Worker: &store.Worker{
					WorkerReportedName:    "base update with worker reported fields",
					WorkerReportedAddress: "base update with worker reported fields",
				},
			},
			mask: []string{"WorkerReportedName", "WorkerReportedAddress"},
			assert: func(t *testing.T, init, up *Worker) {
				t.Helper()
				assert.Equal(t, "base update with worker reported fields", up.WorkerReportedAddress)
				assert.Equal(t, "base update with worker reported fields", up.WorkerReportedName)
				assert.Greater(t, up.GetUpdateTime().AsTime(), up.GetCreateTime().AsTime())
				assert.Equal(t, uint32(1), up.Version)
				assert.NotNil(t, up.GetLastStatusTime())
				assert.Equal(t, up.GetLastStatusTime().AsTime(), up.GetUpdateTime().AsTime())
			},
		},
		{
			name: "worker reported update with base",
			initial: Worker{
				Worker: &store.Worker{
					ScopeId:               scope.Global.String(),
					PublicId:              newId(),
					WorkerReportedAddress: "worker reported update with base",
					WorkerReportedName:    "worker reported update with base",
				},
			},
			update: Worker{
				Worker: &store.Worker{
					Description: "worker reported update with base",
				},
			},
			mask: []string{"Description"},
			assert: func(t *testing.T, init, up *Worker) {
				t.Helper()
				assert.Equal(t, "worker reported update with base", up.Description)
				assert.Greater(t, up.GetUpdateTime().AsTime(), up.GetCreateTime().AsTime())
				assert.Equal(t, uint32(2), up.Version)
				assert.NotNil(t, up.GetLastStatusTime())
				assert.Equal(t, init.GetLastStatusTime(), up.GetLastStatusTime())
			},
		},
		{
			name: "worker reported update name to unprintable",
			initial: Worker{
				Worker: &store.Worker{
					ScopeId:               scope.Global.String(),
					PublicId:              newId(),
					WorkerReportedAddress: "worker reported update name to unprintable",
					WorkerReportedName:    "worker reported update name to unprintable",
				},
			},
			update: Worker{
				Worker: &store.Worker{
					WorkerReportedName: "unprintable \u0008 name",
				},
			},
			mask:            []string{"WorkerReportedName"},
			wantUpdateError: true,
		},
		{
			name: "worker reported clearing address",
			initial: Worker{
				Worker: &store.Worker{
					ScopeId:               scope.Global.String(),
					PublicId:              newId(),
					WorkerReportedAddress: "worker reported clearing address",
					WorkerReportedName:    "worker reported clearing address",
				},
			},
			update: Worker{
				Worker: &store.Worker{},
			},
			nullMask:        []string{"WorkerReportedAddress"},
			wantUpdateError: true,
		},
		{
			name: "worker reported updating worker reported",
			initial: Worker{
				Worker: &store.Worker{
					ScopeId:               scope.Global.String(),
					PublicId:              newId(),
					WorkerReportedAddress: "start",
					WorkerReportedName:    "start",
				},
			},
			update: Worker{
				Worker: &store.Worker{
					WorkerReportedAddress: "worker reported updating worker reported",
				},
			},
			mask: []string{"WorkerReportedAddress"},
			assert: func(t *testing.T, init, up *Worker) {
				t.Helper()
				assert.Equal(t, "worker reported updating worker reported", up.GetWorkerReportedAddress())
				assert.NotNil(t, up.GetLastStatusTime())
				assert.Greater(t, up.GetLastStatusTime().AsTime(), init.GetLastStatusTime().AsTime())
				// We don't modify the worker version while operating only on the worker fields
				assert.Greater(t, up.GetUpdateTime().AsTime(), up.GetCreateTime().AsTime())
				assert.Equal(t, uint32(1), up.Version)
			},
		},
		{
			name: "worker reported clearing worker reported name",
			initial: Worker{
				Worker: &store.Worker{
					ScopeId:               scope.Global.String(),
					PublicId:              newId(),
					WorkerReportedAddress: "worker reported clearing worker reported name",
					WorkerReportedName:    "worker reported clearing worker reported name",
				},
			},
			update: Worker{
				Worker: &store.Worker{},
			},
			nullMask:        []string{"WorkerReportedName"},
			wantUpdateError: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			init := tc.initial.clone()
			require.NoError(t, rw.Create(ctx, init))
			up := tc.update.clone()
			up.PublicId = init.PublicId
			_, err := rw.Update(ctx, up, tc.mask, tc.nullMask)
			if tc.wantUpdateError {
				assert.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}
			tc.assert(t, init.clone(), up.clone())
		})
	}
}

func TestWorker_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	ctx := context.Background()

	newId := func() string {
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		return id
	}

	type wanted struct {
		lastStatusUpdated bool
		createError       bool
	}

	cases := []struct {
		name string
		in   Worker
		want wanted
	}{
		{
			name: "base",
			in: Worker{
				Worker: &store.Worker{
					ScopeId:  scope.Global.String(),
					PublicId: newId(),
				},
			},
			want: wanted{},
		},
		{
			name: "with non status fields",
			in: Worker{
				Worker: &store.Worker{
					ScopeId:     scope.Global.String(),
					PublicId:    newId(),
					Name:        "with non status fields",
					Description: "with non status fields",
					Address:     "address",
				},
			},
			want: wanted{},
		},
		{
			name: "with upper case worker reported name",
			in: Worker{
				Worker: &store.Worker{
					ScopeId:               scope.Global.String(),
					PublicId:              newId(),
					WorkerReportedName:    "With Upper Case Worker Reported Name",
					WorkerReportedAddress: "address",
				},
			},
			want: wanted{createError: true},
		},
		{
			name: "with unprintable worker reported name",
			in: Worker{
				Worker: &store.Worker{
					ScopeId:               scope.Global.String(),
					PublicId:              newId(),
					WorkerReportedName:    "unprintable \u0008 worker reported name",
					WorkerReportedAddress: "address",
				},
			},
			want: wanted{createError: true},
		},
		{
			name: "with status fields",
			in: Worker{
				Worker: &store.Worker{
					ScopeId:               scope.Global.String(),
					PublicId:              newId(),
					WorkerReportedName:    "with non status fields",
					WorkerReportedAddress: "with non status fields",
				},
			},
			want: wanted{
				lastStatusUpdated: true,
			},
		},
		{
			name: "with worker reported address",
			in: Worker{
				Worker: &store.Worker{
					ScopeId:               scope.Global.String(),
					PublicId:              newId(),
					WorkerReportedAddress: "with worker reported address",
				},
			},
			want: wanted{
				createError: true,
			},
		},
		{
			// The worker reported address is a required field if any of the
			// worker reported fields are set.
			name: "with worker reported name",
			in: Worker{
				Worker: &store.Worker{
					ScopeId:            scope.Global.String(),
					PublicId:           newId(),
					WorkerReportedName: "with worker reported name",
				},
			},
			want: wanted{
				createError: true,
			},
		},
		{
			name: "non status fields with worker reported fields",
			in: Worker{
				Worker: &store.Worker{
					ScopeId:               scope.Global.String(),
					PublicId:              newId(),
					Name:                  "non status fields with worker reported fields",
					Description:           "non status fields with worker reported fields",
					Address:               "address",
					WorkerReportedAddress: "non status fields with worker reported fields",
					WorkerReportedName:    "non status fields with worker reported fields",
				},
			},
			want: wanted{
				lastStatusUpdated: true,
			},
		},
		{
			// The worker reported address is a required field if any of the
			// worker reported fields are set.
			name: "non status fields with worker reported name",
			in: Worker{
				Worker: &store.Worker{
					ScopeId:            scope.Global.String(),
					PublicId:           newId(),
					Name:               "non status fields with worker reported name",
					Description:        "non status fields with worker reported name",
					Address:            "address",
					WorkerReportedName: "non status fields with worker reported name",
				},
			},
			want: wanted{
				createError: true,
			},
		},
		{
			name: "non status fields with worker reported address",
			in: Worker{
				Worker: &store.Worker{
					ScopeId:               scope.Global.String(),
					PublicId:              newId(),
					Name:                  "non status fields with worker reported address",
					Description:           "non status fields with worker reported address",
					Address:               "address",
					WorkerReportedAddress: "non status fields with worker reported address",
				},
			},
			want: wanted{
				createError: true,
			},
		},
		{
			name: "non status fields with worker reported keyid",
			in: Worker{
				Worker: &store.Worker{
					ScopeId:     scope.Global.String(),
					PublicId:    newId(),
					Name:        "non status fields with worker reported keyid",
					Description: "non status fields with worker reported keyid",
					Address:     "address",
					KeyId:       "non status fields with worker reported keyid",
				},
			},
			want: wanted{
				createError: true,
			},
		},
		{
			name: "invalid- worker reporting name and key id",
			in: Worker{
				Worker: &store.Worker{
					ScopeId:            scope.Global.String(),
					PublicId:           newId(),
					Address:            "address",
					KeyId:              "non status fields with worker reported keyid",
					WorkerReportedName: "non status fields with worker reported name",
				},
			},
			want: wanted{
				createError: true,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.in.clone()
			err := rw.Create(ctx, w)
			if tc.want.createError {
				assert.Error(t, err)
				return
			} else {
				assert.NoError(t, err)
			}

			if tc.want.lastStatusUpdated {
				assert.NotNil(t, w.GetLastStatusTime())
			} else {
				assert.Nil(t, w.GetLastStatusTime())
			}

			assert.NotNil(t, w.GetCreateTime())
			assert.Equal(t, w.GetCreateTime(), w.GetUpdateTime())
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
				apiTags: []*Tag{
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
