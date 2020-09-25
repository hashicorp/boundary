package password

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArgon2Configuration_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethods := TestAuthMethods(t, conn, o.GetPublicId(), 1)
	authMethod := authMethods[0]
	authMethodId := authMethod.GetPublicId()
	ctx := context.Background()

	// There should already be a configuration when an authMethod is created.
	t.Run("default-configuration", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		var confs []*Argon2Configuration
		err := rw.SearchWhere(ctx, &confs, "password_method_id = ?", []interface{}{authMethodId})
		require.NoError(err)
		require.Equal(1, len(confs))
		got := confs[0]
		want := &Argon2Configuration{
			Argon2Configuration: &store.Argon2Configuration{
				PrivateId:        got.GetPrivateId(),
				CreateTime:       got.GetCreateTime(),
				PasswordMethodId: authMethodId,
				Iterations:       3,
				Memory:           64 * 1024,
				Threads:          1,
				SaltLength:       32,
				KeyLength:        32,
			},
		}
		assert.Equal(want, got)
	})
	t.Run("no-duplicate-configurations", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		got := NewArgon2Configuration()
		require.NotNil(got)
		var err error
		got.PrivateId, err = newArgon2ConfigurationId()
		require.NoError(err)
		got.PasswordMethodId = authMethodId
		err = rw.Create(ctx, got)
		assert.Error(err)
	})
	t.Run("multiple-configurations", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		var confs []*Argon2Configuration
		err := rw.SearchWhere(ctx, &confs, "password_method_id = ?", []interface{}{authMethodId})
		require.NoError(err)
		assert.Equal(1, len(confs))

		c1 := NewArgon2Configuration()
		require.NotNil(c1)
		c1.PrivateId, err = newArgon2ConfigurationId()
		require.NoError(err)
		c1.PasswordMethodId = authMethodId
		c1.Iterations = c1.Iterations + 1
		c1.Threads = c1.Threads + 1
		err = rw.Create(ctx, c1)
		assert.NoError(err)

		c2 := NewArgon2Configuration()
		require.NotNil(c2)
		c2.PrivateId, err = newArgon2ConfigurationId()
		require.NoError(err)
		c2.PasswordMethodId = authMethodId
		c2.Memory = 32 * 1024
		c2.SaltLength = 16
		c2.KeyLength = 16
		err = rw.Create(ctx, c2)
		assert.NoError(err)

		confs = nil
		err = rw.SearchWhere(ctx, &confs, "password_method_id = ?", []interface{}{authMethodId})
		require.NoError(err)
		assert.Equal(3, len(confs))
	})
}

func TestArgon2Configuration_Readonly(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	changeIterations := func() func(*Argon2Configuration) (*Argon2Configuration, []string) {
		return func(c *Argon2Configuration) (*Argon2Configuration, []string) {
			c.Iterations = c.Iterations + 1
			return c, []string{"Iterations"}
		}
	}
	changeThreads := func() func(*Argon2Configuration) (*Argon2Configuration, []string) {
		return func(c *Argon2Configuration) (*Argon2Configuration, []string) {
			c.Threads = c.Threads + 1
			return c, []string{"Threads"}
		}
	}
	changeMemory := func() func(*Argon2Configuration) (*Argon2Configuration, []string) {
		return func(c *Argon2Configuration) (*Argon2Configuration, []string) {
			c.Memory = c.Memory + 1
			return c, []string{"Memory"}
		}
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethods := TestAuthMethods(t, conn, o.GetPublicId(), 1)
	authMethod := authMethods[0]
	authMethodId := authMethod.GetPublicId()

	var tests = []struct {
		name  string
		chgFn func(*Argon2Configuration) (*Argon2Configuration, []string)
	}{
		{
			name:  "iterations",
			chgFn: changeIterations(),
		},
		{
			name:  "threads",
			chgFn: changeThreads(),
		},
		{
			name:  "Memory",
			chgFn: changeMemory(),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var confs []*Argon2Configuration
			err := rw.SearchWhere(context.Background(), &confs, "password_method_id = ?", []interface{}{authMethodId})
			require.NoError(err)
			assert.Greater(len(confs), 0)
			orig := confs[0]
			changed, masks := tt.chgFn(orig)

			require.NotEmpty(changed.GetPrivateId())

			count, err := rw.Update(context.Background(), changed, masks, nil)
			assert.Error(err)
			assert.Equal(0, count)
		})
	}

}

func TestArgon2Configuration_Validate(t *testing.T) {
	var tests = []struct {
		name string
		in   *Argon2Configuration
		want error
	}{
		{
			name: "nil-configuration",
			in:   nil,
			want: ErrInvalidConfiguration,
		},
		{
			name: "nil-embedded-config",
			in:   &Argon2Configuration{},
			want: ErrInvalidConfiguration,
		},
		{
			name: "valid-default",
			in:   NewArgon2Configuration(),
		},
		{
			name: "valid-changes",
			in: &Argon2Configuration{
				Argon2Configuration: &store.Argon2Configuration{
					Iterations: 3 * 2,
					Memory:     32 * 1024,
					Threads:    10,
					SaltLength: 16,
					KeyLength:  16,
				},
			},
		},
		{
			name: "invalid-iterations",
			in: &Argon2Configuration{
				Argon2Configuration: &store.Argon2Configuration{
					Iterations: 0,
					Memory:     1,
					Threads:    1,
					SaltLength: 1,
					KeyLength:  1,
				},
			},
			want: ErrInvalidConfiguration,
		},
		{
			name: "invalid-memory",
			in: &Argon2Configuration{
				Argon2Configuration: &store.Argon2Configuration{
					Iterations: 1,
					Memory:     0,
					Threads:    1,
					SaltLength: 1,
					KeyLength:  1,
				},
			},
			want: ErrInvalidConfiguration,
		},
		{
			name: "invalid-threads",
			in: &Argon2Configuration{
				Argon2Configuration: &store.Argon2Configuration{
					Iterations: 1,
					Memory:     1,
					Threads:    0,
					SaltLength: 1,
					KeyLength:  1,
				},
			},
			want: ErrInvalidConfiguration,
		},
		{
			name: "invalid-salt-length",
			in: &Argon2Configuration{
				Argon2Configuration: &store.Argon2Configuration{
					Iterations: 1,
					Memory:     1,
					Threads:    1,
					SaltLength: 0,
					KeyLength:  1,
				},
			},
			want: ErrInvalidConfiguration,
		},
		{
			name: "invalid-key-length",
			in: &Argon2Configuration{
				Argon2Configuration: &store.Argon2Configuration{
					Iterations: 1,
					Memory:     1,
					Threads:    1,
					SaltLength: 1,
					KeyLength:  0,
				},
			},
			want: ErrInvalidConfiguration,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got := tt.in.validate()
			if tt.want == nil {
				assert.NoErrorf(got, "valid argon2 configuration: %+v", tt.in)
				return
			}
			require.Error(got)
			assert.Truef(errors.Is(got, tt.want), "want err: %q got: %q", tt.want, got)
		})
	}
}

func testArgon2Confs(t *testing.T, conn *gorm.DB, authMethodId string, count int) []*Argon2Configuration {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	rw := db.New(conn)
	var confs []*Argon2Configuration
	err := rw.SearchWhere(context.Background(), &confs, "password_method_id = ?", []interface{}{authMethodId})
	require.NoError(err)
	assert.Equal(1, len(confs))
	base := confs[0]
	for i := 0; i < count; i++ {
		conf := NewArgon2Configuration()
		require.NotNil(conf)
		conf.PasswordMethodId = authMethodId
		conf.PrivateId, err = newArgon2ConfigurationId()
		require.NoError(err)

		conf.Iterations = base.Iterations + uint32(i+1)
		conf.Threads = base.Threads + uint32(i+1)
		err = rw.Create(context.Background(), conf)
		require.NoError(err)
		confs = append(confs, conf)
	}
	return confs
}

func TestArgon2Credential_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	auts := TestAuthMethods(t, conn, o.GetPublicId(), 1)
	aut := auts[0]
	accts := TestAccounts(t, conn, aut.PublicId, 5)
	confs := testArgon2Confs(t, conn, accts[0].AuthMethodId, 1)

	type args struct {
		accountId string
		password  string
		conf      *Argon2Configuration
	}
	var tests = []struct {
		name      string
		args      args
		want      *Argon2Credential
		wantIsErr error
	}{
		{
			name: "blank-accountId",
			args: args{
				accountId: "",
				password:  "foobarcity",
				conf:      confs[0],
			},
			want:      nil,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "blank-password",
			args: args{
				accountId: accts[0].PublicId,
				password:  "",
				conf:      confs[0],
			},
			want:      nil,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "nil-configuration",
			args: args{
				accountId: accts[0].PublicId,
				password:  "foobarcity",
				conf:      nil,
			},
			want:      nil,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "valid-password",
			args: args{
				accountId: accts[0].PublicId,
				password:  "foobarcity",
				conf:      confs[0],
			},
			want: &Argon2Credential{
				Argon2Credential: &store.Argon2Credential{
					PasswordAccountId: accts[0].PublicId,
					PasswordConfId:    confs[0].PrivateId,
				},
			},
		},
		{
			name: "traditional-chinese-characters-password",
			args: args{
				accountId: accts[1].PublicId,
				password:  "漢字𫝆𫝑𫝜𫝓𫝶𫝼𫞉𫞔𫞩𫞬",
				conf:      confs[0],
			},
			want: &Argon2Credential{
				Argon2Credential: &store.Argon2Credential{
					PasswordAccountId: accts[1].PublicId,
					PasswordConfId:    confs[0].PrivateId,
				},
			},
		},
		{
			name: "emoji-password",
			args: args{
				accountId: accts[2].PublicId,
				password:  "😃  😀 😅 😘🤔 😑🤢🤠😰",
				conf:      confs[0],
			},
			want: &Argon2Credential{
				Argon2Credential: &store.Argon2Credential{
					PasswordAccountId: accts[2].PublicId,
					PasswordConfId:    confs[0].PrivateId,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newArgon2Credential(tt.args.accountId, tt.args.password, tt.args.conf)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)

			err = got.encrypt(context.Background(), wrapper)
			require.NoError(err)
			err = rw.Create(context.Background(), got)
			assert.NoError(err)

			if tt.want == nil {
				return
			}

			gotCred := &Argon2Credential{
				Argon2Credential: &store.Argon2Credential{
					PrivateId: got.PrivateId,
				},
			}
			err = rw.LookupById(context.Background(), gotCred)
			require.NoError(err)
			assert.Equal(tt.want.PasswordAccountId, gotCred.PasswordAccountId)
			assert.Equal(tt.want.PasswordConfId, gotCred.PasswordConfId)
		})
	}
}
