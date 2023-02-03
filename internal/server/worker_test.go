// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestWorkerCanonicalTags(t *testing.T) {
	w := NewWorker(scope.Global.String())
	w.apiTags = []*Tag{
		{Key: "key", Value: "apis unique"},
		{Key: "key", Value: "shared"},
		{Key: "key2", Value: "apis key2 unique"},
	}
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

	t.Run("kms worker", func(t *testing.T) {
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		id = strings.ToLower(id)
		w := NewWorker(scope.Global.String(),
			WithName(id),
			WithAddress("address"))
		w.Type = KmsWorkerType.String()
		w.PublicId = id
		require.NoError(t, rw.Create(ctx, w))

		got := getAggWorker(id)
		assert.Equal(t, KmsWorkerType.String(), got.GetType())
		assert.Equal(t, id, got.GetPublicId())
		assert.Equal(t, scope.Global.String(), got.GetScopeId())
		assert.Equal(t, id, got.GetName())
		assert.Equal(t, "address", got.GetAddress())
		assert.Equal(t, uint32(1), got.GetVersion())
		assert.NotNil(t, got.GetLastStatusTime())
		assert.NotNil(t, got.GetReleaseVersion())
		assert.Empty(t, got.CanonicalTags())
	})

	// Worker with status
	t.Run("Worker with status", func(t *testing.T) {
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		w := NewWorker(scope.Global.String(),
			WithAddress("address"),
			WithName(strings.ToLower(id)))
		w.Type = KmsWorkerType.String()
		w.PublicId = id
		require.NoError(t, rw.Create(ctx, w))

		got := getAggWorker(id)
		assert.Equal(t, id, got.GetPublicId())
		assert.Equal(t, uint32(1), got.GetVersion())
		assert.NotNil(t, got.GetLastStatusTime())
		assert.NotNil(t, got.GetReleaseVersion())
		assert.Equal(t, strings.ToLower(id), got.GetName())
		assert.Equal(t, "address", got.GetAddress())
	})

	t.Run("Worker with a config tag", func(t *testing.T) {
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		w := NewWorker(scope.Global.String(),
			WithAddress("address"),
			WithName(strings.ToLower(id)))
		w.Type = KmsWorkerType.String()
		w.PublicId = id
		require.NoError(t, rw.Create(ctx, w))
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
		assert.NotNil(t, got.GetReleaseVersion())
		assert.Empty(t, got.apiTags)
		assert.Equal(t, got.configTags, []*Tag{{Key: "key", Value: "val"}})
	})

	t.Run("Worker with many config tag", func(t *testing.T) {
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		w := NewWorker(scope.Global.String(),
			WithAddress("address"),
			WithName(strings.ToLower(id)))
		w.Type = KmsWorkerType.String()
		w.PublicId = id
		require.NoError(t, rw.Create(ctx, w))
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
	})

	t.Run("Worker with an api tag", func(t *testing.T) {
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		w := NewWorker(scope.Global.String(),
			WithAddress("address"),
			WithName(strings.ToLower(id)))
		w.Type = KmsWorkerType.String()
		w.PublicId = id
		require.NoError(t, rw.Create(ctx, w))
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
	})

	// Worker with mix of tag sources
	t.Run("Worker with mix of tag sources", func(t *testing.T) {
		id, err := newWorkerId(ctx)
		require.NoError(t, err)
		w := NewWorker(scope.Global.String(),
			WithAddress("address"),
			WithName(strings.ToLower(id)))
		w.Type = KmsWorkerType.String()
		w.PublicId = id
		require.NoError(t, rw.Create(ctx, w))
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
	})
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
			name: "kms update address",
			initial: Worker{
				Worker: &store.Worker{
					Type:             KmsWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "kms update address",
					Address:          "kms update address",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			update: Worker{
				Worker: &store.Worker{
					Address: "updated kms update address",
				},
			},
			mask: []string{"Address"},
			assert: func(t *testing.T, init, up *Worker) {
				t.Helper()
				assert.Equal(t, "kms update address", up.Name)
				assert.Equal(t, "updated kms update address", up.Address)
				assert.Greater(t, up.GetUpdateTime().AsTime(), up.GetCreateTime().AsTime())
				assert.Equal(t, up.GetLastStatusTime().AsTime(), up.GetUpdateTime().AsTime())
			},
		},
		{
			name: "kms update name",
			initial: Worker{
				Worker: &store.Worker{
					Type:             KmsWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "kms update name",
					Address:          "kms update name",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			update: Worker{
				Worker: &store.Worker{
					Name: "updated kms update name",
				},
			},
			mask:            []string{"Name"},
			wantUpdateError: true,
		},
		{
			name: "kms clear name",
			initial: Worker{
				Worker: &store.Worker{
					Type:             KmsWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "kms clear name",
					Address:          "kms clear name",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			update: Worker{
				Worker: &store.Worker{},
			},
			nullMask:        []string{"Name"},
			wantUpdateError: true,
		},
		{
			name: "pki update address",
			initial: Worker{
				Worker: &store.Worker{
					Type:             PkiWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "pki update address",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			update: Worker{
				Worker: &store.Worker{
					Address: "updated pki update address",
				},
			},
			mask: []string{"Address"},
			assert: func(t *testing.T, init, up *Worker) {
				t.Helper()
				assert.Equal(t, "pki update address", up.Name)
				assert.Equal(t, "updated pki update address", up.Address)
				assert.Greater(t, up.GetUpdateTime().AsTime(), up.GetCreateTime().AsTime())
				assert.Equal(t, up.GetLastStatusTime().AsTime(), up.GetUpdateTime().AsTime())
			},
		},
		{
			name: "pki update name",
			initial: Worker{
				Worker: &store.Worker{
					Type:             PkiWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "pki update name",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			update: Worker{
				Worker: &store.Worker{
					Name: "updated pki update name",
				},
			},
			mask: []string{"Name"},
			assert: func(t *testing.T, init, up *Worker) {
				t.Helper()
				assert.Equal(t, "updated pki update name", up.Name)
				assert.Greater(t, up.GetUpdateTime().AsTime(), up.GetCreateTime().AsTime())
				assert.Nil(t, up.GetLastStatusTime())
			},
		},
		{
			name: "pki update description",
			initial: Worker{
				Worker: &store.Worker{
					Type:             PkiWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "pki update description",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			update: Worker{
				Worker: &store.Worker{
					Description: "updated pki update description",
				},
			},
			mask: []string{"Description"},
			assert: func(t *testing.T, init, up *Worker) {
				t.Helper()
				assert.Equal(t, "pki update description", up.Name)
				assert.Equal(t, "updated pki update description", up.Description)
				assert.Greater(t, up.GetUpdateTime().AsTime(), up.GetCreateTime().AsTime())
				assert.Nil(t, up.GetLastStatusTime())
			},
		},
		{
			name: "pki clear address",
			initial: Worker{
				Worker: &store.Worker{
					Type:             PkiWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "pki clear address",
					Address:          "pki clear address",
					LastStatusTime:   &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(time.Hour))},
					OperationalState: ActiveOperationalState.String(),
				},
			},
			update: Worker{
				Worker: &store.Worker{},
			},
			nullMask:        []string{"Address"},
			wantUpdateError: true,
		},
		{
			name: "pki clear name",
			initial: Worker{
				Worker: &store.Worker{
					Type:             PkiWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "pki clear name",
					Address:          "pki clear name",
					LastStatusTime:   &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(time.Hour))},
					OperationalState: ActiveOperationalState.String(),
				},
			},
			update: Worker{
				Worker: &store.Worker{},
			},
			nullMask: []string{"Name"},
			assert: func(t *testing.T, init, up *Worker) {
				t.Helper()
				assert.Empty(t, up.Name)
				assert.Greater(t, up.GetUpdateTime().AsTime(), up.GetCreateTime().AsTime())
				assert.Greater(t, up.GetLastStatusTime().AsTime(), up.GetUpdateTime().AsTime())
				assert.Less(t, up.GetLastStatusTime().AsTime(), time.Now().Add(time.Hour))
			},
		},
		{
			name: "pki update name to capital",
			initial: Worker{
				Worker: &store.Worker{
					Type:             PkiWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "pki update name to capital",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			update: Worker{
				Worker: &store.Worker{
					Name: "PKI Update Name To Capital",
				},
			},
			mask:            []string{"Name"},
			wantUpdateError: true,
		},
		{
			name: "pki update name to unprintable",
			initial: Worker{
				Worker: &store.Worker{
					Type:             PkiWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "worker reported update name to unprintable",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			update: Worker{
				Worker: &store.Worker{
					Name: "unprintable \u0008 name",
				},
			},
			mask:            []string{"Name"},
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
				fmt.Println(err)
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
			name: "kms base",
			in: Worker{
				Worker: &store.Worker{
					Type:             KmsWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Address:          "address",
					Name:             "kms base",
					Description:      "kms base",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			want: wanted{lastStatusUpdated: true},
		},
		{
			name: "kms with no name field",
			in: Worker{
				Worker: &store.Worker{
					Type:             KmsWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Address:          "address",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			want: wanted{createError: true},
		},
		{
			name: "kms with no address field",
			in: Worker{
				Worker: &store.Worker{
					Type:             KmsWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "kms with no address field",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			want: wanted{createError: true},
		},
		{
			name: "kms with upper case name",
			in: Worker{
				Worker: &store.Worker{
					Type:             KmsWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "With Upper Case Worker Reported Name",
					Address:          "address",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			want: wanted{createError: true},
		},
		{
			name: "kms with unprintable worker reported name",
			in: Worker{
				Worker: &store.Worker{
					Type:             KmsWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "unprintable \u0008 worker reported name",
					Address:          "address",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			want: wanted{createError: true},
		},
		// PKI workers are not created in a way that should set the address
		// or the last_status_time.
		{
			name: "pki base",
			in: Worker{
				Worker: &store.Worker{
					Type:             PkiWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "pki base",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			want: wanted{},
		},
		{
			name: "pki with no name field",
			in: Worker{
				Worker: &store.Worker{
					Type:             PkiWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					OperationalState: ActiveOperationalState.String(),
				},
			},
			want: wanted{},
		},
		{
			name: "pki with address field",
			in: Worker{
				Worker: &store.Worker{
					Type:             PkiWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Address:          "address",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			want: wanted{createError: true},
		},
		{
			name: "pki with upper case name",
			in: Worker{
				Worker: &store.Worker{
					Type:             PkiWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "PKI With Upper Case Worker Reported Name",
					Address:          "address",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			want: wanted{createError: true},
		},
		{
			name: "pki with unprintable worker reported name",
			in: Worker{
				Worker: &store.Worker{
					Type:             PkiWorkerType.String(),
					ScopeId:          scope.Global.String(),
					PublicId:         newId(),
					Name:             "unprintable \u0008 worker reported name",
					Address:          "address",
					OperationalState: ActiveOperationalState.String(),
				},
			},
			want: wanted{createError: true},
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

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	type args struct {
		scopeId string
		opts    []Option
	}

	tests := []struct {
		name string
		args args
		want *Worker
	}{
		{
			name: "missing-scope-id",
			args: args{},
			want: &Worker{
				Worker: &store.Worker{
					OperationalState: ActiveOperationalState.String(),
				},
			},
		},
		{
			name: "global-scope-id",
			args: args{
				scopeId: scope.Global.String(),
			},
			want: &Worker{
				Worker: &store.Worker{
					ScopeId:          scope.Global.String(),
					OperationalState: ActiveOperationalState.String(),
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
					ScopeId:          org.GetPublicId(),
					OperationalState: ActiveOperationalState.String(),
				},
			},
		},
		{
			name: "project-scope-id",
			args: args{
				scopeId: prj.GetPublicId(),
			},
			want: &Worker{
				Worker: &store.Worker{
					ScopeId:          prj.GetPublicId(),
					OperationalState: ActiveOperationalState.String(),
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
					ScopeId:          scope.Global.String(),
					Name:             "foo",
					OperationalState: ActiveOperationalState.String(),
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
					ScopeId:          scope.Global.String(),
					Description:      "foo",
					OperationalState: ActiveOperationalState.String(),
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
					ScopeId:          scope.Global.String(),
					Address:          "foo",
					OperationalState: ActiveOperationalState.String(),
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
					ScopeId:          scope.Global.String(),
					OperationalState: ActiveOperationalState.String(),
				},
				inputTags: []*Tag{
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
		})
	}
}
