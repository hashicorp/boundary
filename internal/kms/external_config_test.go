package kms

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestExternalConfig_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, proj := iam.TestScopes(t, conn)
	type args struct {
		scopeId  string
		confType KmsType
		config   string
		opt      []Option
	}
	tests := []struct {
		name          string
		args          args
		want          *ExternalConfig
		wantErr       bool
		wantIsErr     error
		create        bool
		wantCreateErr bool
	}{
		{
			name: "empty-scopeId",
			args: args{
				confType: AeadKms,
				config:   "{}",
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-config",
			args: args{
				scopeId:  org.PublicId,
				confType: AeadKms,
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "valid-org-config",
			args: args{
				scopeId:  org.PublicId,
				confType: AeadKms,
				config:   "{}",
			},
			want: func() *ExternalConfig {
				c := allocExternalConfig()
				c.ScopeId = org.PublicId
				c.Type = AeadKms.String()
				c.Config = "{}"
				return &c
			}(),
			create: true,
		},
		{
			name: "valid-global-config",
			args: args{
				scopeId:  "global",
				confType: AeadKms,
				config:   "{}",
			},
			want: func() *ExternalConfig {
				c := allocExternalConfig()
				c.ScopeId = "global"
				c.Type = AeadKms.String()
				c.Config = "{}"
				return &c
			}(),
			create: true,
		},
		{
			// external kms configs are not valid at the project scope level.
			name: "invalid-project-config",
			args: args{
				scopeId:  proj.PublicId,
				confType: AeadKms,
				config:   "{}",
			},
			want: func() *ExternalConfig {
				c := allocExternalConfig()
				c.ScopeId = proj.PublicId
				c.Type = AeadKms.String()
				c.Config = "{}"
				return &c
			}(),
			create:        true,
			wantCreateErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(allocExternalConfig()).Error)
			got, err := NewExternalConfig(tt.args.scopeId, tt.args.confType, tt.args.config, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Is(err, tt.wantIsErr))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := newExternalConfigId()
				require.NoError(err)
				got.PrivateId = id

				err = got.encrypt(context.Background(), wrapper)
				require.NoError(err)

				err = db.New(conn).Create(context.Background(), got)
				if tt.wantCreateErr {
					assert.Error(err)
					return
				} else {
					assert.NoError(err)
				}
			}
		})
	}
}

// TestExternalConfig_Update only covers updating the config and version tables.
// the immutable fields (private_id, scope_id, type, and create_time) are
// tested in TestExternalConfig_ImmutableFields()
func TestExternalConfig_Update(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, conn)
	rw := db.New(conn)
	type args struct {
		config         string
		version        uint32
		fieldMaskPaths []string
		nullPaths      []string
	}
	tests := []struct {
		name           string
		args           args
		wantRowsUpdate int
		wantErr        bool
	}{
		{
			name: "valid",
			args: args{
				config:         `{"valid": "valid"}`,
				version:        uint32(4), // this will be accepted, but the trigger will override it to the correct value of 2
				fieldMaskPaths: []string{"CtConfig", "Version"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "invalid",
			args: args{
				config:    "",
				nullPaths: []string{"Config"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			c := TestExternalConfig(t, conn, wrapper, org.PublicId, AeadKms, "{}")

			updateConfig := allocExternalConfig()
			updateConfig.PrivateId = c.PrivateId
			updateConfig.Config = tt.args.config
			updateConfig.Version = tt.args.version
			err := updateConfig.encrypt(context.Background(), wrapper)
			require.NoError(err)

			updatedRows, err := rw.Update(context.Background(), &updateConfig, tt.args.fieldMaskPaths, tt.args.nullPaths)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, updatedRows)
				err = db.TestVerifyOplog(t, rw, c.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.NotEqual(c.UpdateTime, updateConfig.UpdateTime)
			foundConfig := allocExternalConfig()
			foundConfig.PrivateId = c.PrivateId
			err = rw.LookupById(context.Background(), &foundConfig)
			require.NoError(err)
			err = foundConfig.decrypt(context.Background(), wrapper)
			require.NoError(err)

			assert.True(proto.Equal(updateConfig, foundConfig))
			assert.Equal(uint32(2), foundConfig.Version)
			if len(tt.args.nullPaths) != 0 {
				dbassert := dbassert.New(t, db.New(conn))
				for _, f := range tt.args.nullPaths {
					dbassert.IsNull(&foundConfig, f)
				}
			}
		})
	}
}

func TestExternalConfig_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	org, _ := iam.TestScopes(t, conn)

	tests := []struct {
		name            string
		config          *ExternalConfig
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			config:          TestExternalConfig(t, conn, wrapper, org.PublicId, AeadKms, "{}"),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			config: func() *ExternalConfig {
				c := allocExternalConfig()
				id, err := newExternalConfigId()
				require.NoError(t, err)
				c.PrivateId = id
				c.ScopeId = org.PublicId
				c.Type = AeadKms.String()
				c.Config = "{}"
				return &c
			}(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteConf := allocExternalConfig()
			deleteConf.PrivateId = tt.config.PrivateId
			deletedRows, err := rw.Delete(context.Background(), &deleteConf)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundCfg := allocExternalConfig()
			foundCfg.PrivateId = tt.config.PrivateId
			err = rw.LookupById(context.Background(), &foundCfg)
			require.Error(err)
			assert.True(errors.Is(db.ErrRecordNotFound, err))
		})
	}
}

func TestExternalConfig_Clone(t *testing.T) {
	t.Parallel()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, conn)
		k := TestExternalConfig(t, conn, wrapper, org.PublicId, AeadKms, "{}")
		cp := k.Clone()
		assert.True(proto.Equal(cp.(*ExternalConfig).ExternalConfig, k.ExternalConfig))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, conn)
		org2, _ := iam.TestScopes(t, conn)
		k := TestExternalConfig(t, conn, wrapper, org.PublicId, AeadKms, "{}")
		k2 := TestExternalConfig(t, conn, wrapper, org2.PublicId, AeadKms, "{}")

		cp := k.Clone()
		assert.True(!proto.Equal(cp.(*ExternalConfig).ExternalConfig, k2.ExternalConfig))
	})
}

func TestExternalConfig_SetTableName(t *testing.T) {
	defaultTableName := defaultExternalConfigTableName
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := allocExternalConfig()
			require.Equal(defaultTableName, def.TableName())
			s := &ExternalConfig{
				ExternalConfig: &store.ExternalConfig{},
				tableName:      tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
