package kms

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExternalConfig_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
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
				confType: DevKms,
				config:   "{}",
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-config",
			args: args{
				scopeId:  org.PublicId,
				confType: DevKms,
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "bad-json-config",
			args: args{
				scopeId:  org.PublicId,
				confType: DevKms,
				config:   "{",
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "valid-org-config",
			args: args{
				scopeId:  org.PublicId,
				confType: DevKms,
				config:   "{}",
			},
			want: func() *ExternalConfig {
				c := allocExternalConfig()
				c.ScopeId = org.PublicId
				c.Type = DevKms.String()
				c.Config = "{}"
				return &c
			}(),
			create: true,
		},
		{
			name: "valid-global-config",
			args: args{
				scopeId:  "global",
				confType: DevKms,
				config:   "{}",
			},
			want: func() *ExternalConfig {
				c := allocExternalConfig()
				c.ScopeId = "global"
				c.Type = DevKms.String()
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
				confType: DevKms,
				config:   "{}",
			},
			want: func() *ExternalConfig {
				c := allocExternalConfig()
				c.ScopeId = proj.PublicId
				c.Type = DevKms.String()
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
				err = db.New(conn).Create(context.Background(), got)
				conn.LogMode(true)
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
