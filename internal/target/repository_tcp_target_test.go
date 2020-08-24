package target

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateTcpTarget(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, testKms)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	cats := static.TestCatalogs(t, conn, org.PublicId, 1)
	hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 2)
	var sets []string
	for _, s := range hsets {
		sets = append(sets, s.PublicId)
	}

	type args struct {
		target *TcpTarget
		opt    []Option
	}
	tests := []struct {
		name         string
		args         args
		wantHostSets []string
		wantErr      bool
		wantIsError  error
	}{
		{
			name: "valid-org",
			args: args{
				target: func() *TcpTarget {
					target, err := NewTcpTarget(org.PublicId, "valid-org",
						WithDescription("valid-org"),
						WithDefaultPort(uint32(22)))
					require.NoError(t, err)
					return target
				}(),
				opt: []Option{WithHostSets(sets)},
			},
			wantErr:      false,
			wantHostSets: sets,
		},
		{
			name: "nil-target",
			args: args{
				target: nil,
			},
			wantErr:     true,
			wantIsError: db.ErrNilParameter,
		},
		{
			name: "nil-target-store",
			args: args{
				target: func() *TcpTarget {
					target := &TcpTarget{}
					return target
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrNilParameter,
		},
		{
			name: "public-id-not-empty",
			args: args{
				target: func() *TcpTarget {
					target, err := NewTcpTarget(org.PublicId, "valid-org", WithDescription("valid-org"), WithDefaultPort(uint32(22)))
					require.NoError(t, err)
					id, err := newTcpTargetId()
					require.NoError(t, err)
					target.PublicId = id
					return target
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-scope-id",
			args: args{
				target: func() *TcpTarget {
					target := allocTcpTarget()
					target.Name = "empty-scope-id"
					require.NoError(t, err)
					return &target
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			target, hostSets, err := repo.CreateTcpTarget(context.Background(), tt.args.target, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(target)
				if tt.wantIsError != nil {
					assert.True(errors.Is(err, tt.wantIsError))
				}
				return
			}
			require.NoError(err)
			assert.NotNil(target.GetPublicId())
			gotIds := make([]string, 0, len(hostSets))
			for _, s := range hostSets {
				gotIds = append(gotIds, s.PublicId)
			}
			assert.Equal(tt.wantHostSets, gotIds)

			foundTarget, foundHostSets, err := repo.LookupTarget(context.Background(), target.GetPublicId())
			assert.NoError(err)
			assert.True(proto.Equal(target.(*TcpTarget), foundTarget.(*TcpTarget)))
			assert.Equal(hostSets, foundHostSets)

			err = db.TestVerifyOplog(t, rw, target.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			// TODO (jimlambrt 9/2020) - unfortunately, we can currently
			// test to make sure that the oplog entry for a target host sets
			// create exist because the db.TestVerifyOplog doesn't really
			// support that level of testing and the previous call to
			// CreateTcpTarget would create an oplog entry for the
			// create on the target even if no host sets were added.   Once
			// TestVerifyOplog supports the appropriate granularity, we should
			// add an appropriate assert.
		})
	}
}
