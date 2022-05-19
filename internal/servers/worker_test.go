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
	"google.golang.org/protobuf/testing/protocmp"
)

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
