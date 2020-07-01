package password

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArgon2Configuration_New(t *testing.T) {
	/*
		insert new configs
		lookup to make sure they are saved

		insert config
		try to insert duplicate
		verify it was not saved
	*/
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	})

	// conn.LogMode(true)
	rw := db.New(conn)

	authMethods := testAuthMethods(t, conn, 1)
	authMethod := authMethods[0]
	authMethodId := authMethod.GetPublicId()
	ctx := context.Background()

	// The order of these tests are important. Some tests have a dependency
	// on prior tests.

	// There should already be a configuration when an authMethod is created.
	t.Run("default-configuration", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		var confs []*Argon2Configuration
		err := rw.SearchWhere(ctx, &confs, "auth_password_method_id = ?", []interface{}{authMethodId})
		require.NoError(err)
		assert.Equal(1, len(confs))
		got := confs[0]
		want := &Argon2Configuration{
			Argon2Configuration: &store.Argon2Configuration{
				PublicId:             got.GetPublicId(),
				CreateTime:           got.GetCreateTime(),
				AuthPasswordMethodId: authMethodId,
				Iterations:           3,
				Memory:               64 * 1024,
				Threads:              1,
				SaltLength:           32,
				KeyLength:            32,
			},
		}
		require.Equal(want, got)
	})
	t.Run("no-duplicate-configurations", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		got, err := NewArgon2Configuration(authMethodId)
		require.NoError(err)
		require.NotNil(got)
		err = rw.Create(ctx, got)
		assert.Error(err)
	})
}

func TestArgon2Configuration_Readonly(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	})

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

	authMethods := testAuthMethods(t, conn, 1)
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
			err := rw.SearchWhere(context.Background(), &confs, "auth_password_method_id = ?", []interface{}{authMethodId})
			require.NoError(err)
			assert.Greater(len(confs), 0)
			orig := confs[0]
			changed, masks := tt.chgFn(orig)

			require.NotEmpty(changed.GetPublicId())

			count, err := rw.Update(context.Background(), changed, masks, nil)
			assert.Error(err)
			assert.Equal(0, count)
		})
	}

}
