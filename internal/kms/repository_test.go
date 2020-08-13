package kms

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewRepository(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	type args struct {
		r       db.Reader
		w       db.Writer
		wrapper wrapping.Wrapper
	}
	tests := []struct {
		name          string
		args          args
		want          *Repository
		wantErr       bool
		wantErrString string
	}{
		{
			name: "valid",
			args: args{
				r:       rw,
				w:       rw,
				wrapper: wrapper,
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				wrapper:      wrapper,
				defaultLimit: db.DefaultLimit,
			},
			wantErr: false,
		},
		{
			name: "nil-wrapper",
			args: args{
				r:       rw,
				w:       rw,
				wrapper: nil,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "error creating db repository with nil wrapper",
		},
		{
			name: "nil-writer",
			args: args{
				r:       rw,
				w:       nil,
				wrapper: wrapper,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "error creating db repository with nil writer",
		},
		{
			name: "nil-reader",
			args: args{
				r:       nil,
				w:       rw,
				wrapper: wrapper,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "error creating db repository with nil reader",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.wrapper)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(err.Error(), tt.wantErrString)
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestRepository_CreateExternalConfig(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	org, proj := iam.TestScopes(t, conn)

	type args struct {
		conf *ExternalConfig
		opt  []Option
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantIsError error
	}{
		{
			name: "valid-org",
			args: args{
				conf: func() *ExternalConfig {
					c, err := NewExternalConfig(org.PublicId, DevKms, "{}")
					assert.NoError(t, err)
					return c
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid-global",
			args: args{
				conf: func() *ExternalConfig {
					c, err := NewExternalConfig("global", DevKms, "{}")
					assert.NoError(t, err)
					return c
				}(),
			},
			wantErr: false,
		},
		{
			name: "invalid-proj",
			args: args{
				conf: func() *ExternalConfig {
					c, err := NewExternalConfig(proj.PublicId, DevKms, "{}")
					assert.NoError(t, err)
					return c
				}(),
			},
			wantErr: true,
		},
		{
			name: "invalid-scope",
			args: args{
				conf: func() *ExternalConfig {
					c, err := NewExternalConfig("o_notAValidScopeId", DevKms, "{}")
					assert.NoError(t, err)
					return c
				}(),
			},
			wantErr: true,
		},
		{
			name: "empty-scope",
			args: args{
				conf: func() *ExternalConfig {
					c, err := NewExternalConfig(org.PublicId, DevKms, "{}")
					assert.NoError(t, err)
					c.ScopeId = ""
					return c
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-conf",
			args: args{
				conf: func() *ExternalConfig {
					c, err := NewExternalConfig(org.PublicId, DevKms, "{}")
					assert.NoError(t, err)
					c.Config = ""
					return c
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "invalid-privateId",
			args: args{
				conf: func() *ExternalConfig {
					c, err := NewExternalConfig(org.PublicId, DevKms, "{}")
					assert.NoError(t, err)
					c.PrivateId = "mustBeEmpty"
					return c
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "nil-conf",
			args: args{
				conf: nil,
			},
			wantErr:     true,
			wantIsError: db.ErrNilParameter,
		},
		{
			name: "nil-store",
			args: args{
				conf: func() *ExternalConfig {
					return &ExternalConfig{
						ExternalConfig: nil,
					}
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrNilParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			c, err := repo.CreateExternalConfig(context.Background(), tt.args.conf, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(c)
				if tt.wantIsError != nil {
					assert.True(errors.Is(err, tt.wantIsError))
				}
				return
			}
			require.NoError(err)
			assert.NotNil(c.CreateTime)
			assert.NotNil(c.UpdateTime)

			foundCfg, err := repo.LookupExternalConfig(context.Background(), c.PrivateId)
			assert.NoError(err)
			assert.True(proto.Equal(foundCfg, c))

			err = db.TestVerifyOplog(t, rw, c.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}
