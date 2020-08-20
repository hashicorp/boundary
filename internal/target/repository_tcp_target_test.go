package target

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
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

	type args struct {
		target     *TcpTarget
		keyWrapper wrapping.Wrapper
		opt        []Option
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
					target, err := NewTcpTarget(org.PublicId, "valid-org", WithDescription("valid-org"), WithDefaultPort(uint32(22)))
					require.NoError(t, err)
					return target
				}(),
				keyWrapper: wrapper,
			},
			wantErr: false,
		},
		{
			name: "nil-target",
			args: args{
				target:     nil,
				keyWrapper: wrapper,
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
				keyWrapper: wrapper,
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
				keyWrapper: wrapper,
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
				keyWrapper: wrapper,
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "nil-wrapper",
			args: args{
				target: func() *TcpTarget {
					target, err := NewTcpTarget(org.PublicId, "valid-org", WithDescription("valid-org"), WithDefaultPort(uint32(22)))
					require.NoError(t, err)
					return target
				}(),
				keyWrapper: nil,
			},
			wantErr:     true,
			wantIsError: db.ErrNilParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			target, hostSets, err := repo.CreateTcpTarget(context.Background(), tt.args.keyWrapper, tt.args.target, tt.args.opt...)
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
			assert.Equal(tt.wantHostSets, hostSets)

			foundTarget, foundHostSets, err := repo.LookupTarget(context.Background(), tt.args.keyWrapper, target.GetPublicId())
			assert.NoError(err)
			assert.True(proto.Equal(target.(*TcpTarget), foundTarget.(*TcpTarget)))
			assert.Equal(hostSets, foundHostSets)

			err = db.TestVerifyOplog(t, rw, target.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}
