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
			name: "invalid-conf",
			args: args{
				conf: func() *ExternalConfig {
					c, err := NewExternalConfig(org.PublicId, DevKms, "{}")
					assert.NoError(t, err)
					c.Config = "{invalid}"
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

func TestRepository_DeleteExternalConfig(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, conn)

	type args struct {
		conf *ExternalConfig
		opt  []Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantIsError     error
	}{
		{
			name: "valid",
			args: args{
				conf: TestExternalConfig(t, conn, org.PublicId, DevKms, "{}"),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-private-id",
			args: args{
				conf: func() *ExternalConfig {
					c := allocExternalConfig()
					return &c
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsError:     db.ErrInvalidParameter,
		},
		{
			name: "not-found",
			args: args{
				conf: func() *ExternalConfig {
					id, err := newExternalConfigId()
					require.NoError(t, err)
					c := allocExternalConfig()
					c.PrivateId = id
					require.NoError(t, err)
					return &c
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsError:     db.ErrRecordNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deletedRows, err := repo.DeleteExternalConfig(context.Background(), tt.args.conf.PrivateId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, deletedRows)
				if tt.wantIsError != nil {
					assert.True(errors.Is(err, tt.wantIsError))
				}
				err = db.TestVerifyOplog(t, rw, tt.args.conf.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundCfg, err := repo.LookupExternalConfig(context.Background(), tt.args.conf.PrivateId)
			assert.Error(err)
			assert.Nil(foundCfg)
			assert.True(errors.Is(err, db.ErrRecordNotFound))

			err = db.TestVerifyOplog(t, rw, tt.args.conf.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_UpdateExternalConfig(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	a := assert.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	a.NoError(err)

	org, _ := iam.TestScopes(t, conn)
	privId := func(s string) *string { return &s }

	type args struct {
		config         *ExternalConfig
		fieldMaskPaths []string
		opt            []Option
		PrivateId      *string
		version        uint32
	}
	tests := []struct {
		name           string
		newScopeId     string
		newGrpOpts     []Option
		args           args
		wantRowsUpdate int
		wantErr        bool
		wantIsError    error
	}{
		{
			name: "valid",
			args: args{
				fieldMaskPaths: []string{"Config"},
				config: func() *ExternalConfig {
					c := allocExternalConfig()
					c.Config = `{"alice":"bob"}`
					return &c
				}(),
				version: uint32(1),
			},
			newScopeId:     org.PublicId,
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "not-found",
			args: args{
				fieldMaskPaths: []string{"Config"},
				config: func() *ExternalConfig {
					c := allocExternalConfig()
					c.Config = `{"alice":"bob"}`
					return &c
				}(),
				version:   uint32(1),
				PrivateId: func() *string { s := "1"; return &s }(),
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrRecordNotFound,
		},
		// {
		// 	name: "null-name",
		// 	args: args{
		// 		name:           "",
		// 		fieldMaskPaths: []string{"Name"},
		// 		ScopeId:        org.PublicId,
		// 	},
		// 	newScopeId:     org.PublicId,
		// 	newGrpOpts:     []Option{WithName("null-name" + id)},
		// 	wantErr:        false,
		// 	wantRowsUpdate: 1,
		// },
		// {
		// 	name: "null-description",
		// 	args: args{
		// 		name:           "",
		// 		fieldMaskPaths: []string{"Description"},
		// 		ScopeId:        org.PublicId,
		// 	},
		// 	newScopeId:     org.PublicId,
		// 	newGrpOpts:     []Option{WithDescription("null-description" + id)},
		// 	wantErr:        false,
		// 	wantRowsUpdate: 1,
		// },
		{
			name: "empty-field-mask",
			args: args{
				fieldMaskPaths: []string{},
				config: func() *ExternalConfig {
					c := allocExternalConfig()
					c.Config = `{"alice":"bob"}`
					return &c
				}(),
				version: uint32(1),
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrEmptyFieldMask,
		},
		{
			name: "nil-fieldmask",
			args: args{
				fieldMaskPaths: nil,
				config: func() *ExternalConfig {
					c := allocExternalConfig()
					c.Config = `{"alice":"bob"}`
					return &c
				}(),
				version: uint32(1),
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrEmptyFieldMask,
		},
		{
			name: "read-only-create-time",
			args: args{
				fieldMaskPaths: []string{"CreateTime"},
				config: func() *ExternalConfig {
					c := allocExternalConfig()
					c.Config = `{"alice":"bob"}`
					return &c
				}(),
				version: uint32(1),
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "read-only-update-time",
			args: args{
				fieldMaskPaths: []string{"UpdateTime"},
				config: func() *ExternalConfig {
					c := allocExternalConfig()
					c.Config = `{"alice":"bob"}`
					return &c
				}(),
				version: uint32(1),
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "read-only-privateId",
			args: args{
				fieldMaskPaths: []string{"PrivateId"},
				config: func() *ExternalConfig {
					c := allocExternalConfig()
					c.PrivateId = org.PublicId
					return &c
				}(),
				version: uint32(1),
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "read-only-scopeId",
			args: args{
				fieldMaskPaths: []string{"ScopeId"},
				config: func() *ExternalConfig {
					c := allocExternalConfig()
					c.ScopeId = org.PublicId
					return &c
				}(),
				version: uint32(1),
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "read-only-type",
			args: args{
				fieldMaskPaths: []string{"type"},
				config: func() *ExternalConfig {
					c := allocExternalConfig()
					c.Type = AliCloudKms.String()
					return &c
				}(),
				version: uint32(1),
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "read-only-version",
			args: args{
				fieldMaskPaths: []string{"version"},
				config: func() *ExternalConfig {
					c := allocExternalConfig()
					c.Version = 100
					return &c
				}(),
				version: uint32(1),
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "unknown-fields",
			args: args{
				fieldMaskPaths: []string{"Alice"},
				config: func() *ExternalConfig {
					c := allocExternalConfig()
					c.Config = `{"alice":"bob"}`
					return &c
				}(),
				version: uint32(1),
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "no-private-id",
			args: args{
				fieldMaskPaths: []string{"Name"},
				config: func() *ExternalConfig {
					c := allocExternalConfig()
					c.Config = `{"alice":"bob"}`
					return &c
				}(),
				version:   uint32(1),
				PrivateId: privId(""),
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantIsError:    db.ErrInvalidParameter,
			wantRowsUpdate: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			c := TestExternalConfig(t, conn, tt.newScopeId, DevKms, "{}")

			tt.args.config.PrivateId = c.PrivateId
			if tt.args.PrivateId != nil {
				tt.args.config.PrivateId = *tt.args.PrivateId
			}
			var cfgAfterUpdate *ExternalConfig
			var updatedRows int
			var err error
			cfgAfterUpdate, updatedRows, err = repo.UpdateExternalConfig(context.Background(), tt.args.config, tt.args.version, tt.args.fieldMaskPaths, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				if tt.wantIsError != nil {
					assert.True(errors.Is(err, tt.wantIsError))
				}
				assert.Nil(cfgAfterUpdate)
				assert.Equal(0, updatedRows)
				err = db.TestVerifyOplog(t, rw, c.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			foundCfg, err := repo.LookupExternalConfig(context.Background(), c.PrivateId)
			require.NoError(err)
			assert.True(proto.Equal(cfgAfterUpdate, foundCfg))
			err = db.TestVerifyOplog(t, rw, c.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}
