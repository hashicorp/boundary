// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	cachedb "github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUser(t *testing.T) {
	ctx := context.Background()
	conn, err := cachedb.Open(ctx)
	require.NoError(t, err)
	rw := db.New(conn)

	t.Run("missing address", func(t *testing.T) {
		u := &user{
			Id: "u1",
		}
		assert.ErrorContains(t, rw.Create(ctx, &u), "constraint failed")
	})

	t.Run("missing id", func(t *testing.T) {
		u := &user{
			Address: "address",
		}
		assert.ErrorContains(t, rw.Create(ctx, &u), "constraint failed")
	})

	t.Run("create success", func(t *testing.T) {
		u := &user{
			Id:      "created",
			Address: "address",
		}
		assert.NoError(t, rw.Create(ctx, &u))
	})

	t.Run("update", func(t *testing.T) {
		u := &user{
			Id:      "update",
			Address: "address",
		}
		require.NoError(t, rw.Create(ctx, &u))
		updatedU := u.clone()
		updatedU.Address = "updated"
		_, err := rw.Update(ctx, updatedU, []string{"address"}, nil)
		require.NoError(t, err)

		lookedUp := u.clone()
		require.NoError(t, rw.LookupById(ctx, lookedUp))
		assert.Equal(t, updatedU.Address, lookedUp.Address)
	})
}

func TestUser_NoMoreTokens(t *testing.T) {
	ctx := context.Background()
	conn, err := cachedb.Open(ctx)
	require.NoError(t, err)
	rw := db.New(conn)

	u := &user{
		Id:      "userId",
		Address: "address",
	}
	require.NoError(t, rw.Create(ctx, u))

	tok1 := &AuthToken{
		UserId: u.Id,
		Id:     "at_1",
	}
	require.NoError(t, rw.Create(ctx, tok1))
	tok2 := &AuthToken{
		UserId: u.Id,
		Id:     "at_2",
	}
	require.NoError(t, rw.Create(ctx, tok2))
	assert.NoError(t, rw.LookupById(ctx, u))

	// deleting a single token doesn't remove the user
	_, err = rw.Exec(ctx, "delete from auth_token where id = ?", []any{tok1.Id})
	require.NoError(t, err)
	assert.NoError(t, rw.LookupById(ctx, u))

	// deleting both tokens _does_ remove the user
	_, err = rw.Exec(ctx, "delete from auth_token", nil)
	require.NoError(t, err)
	assert.True(t, errors.IsNotFoundError(rw.LookupById(ctx, u)))
}

func TestAuthToken_NoMoreKeyringTokens(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)
	rw := db.New(s)

	u := &user{
		Id:      "userId",
		Address: "address",
	}
	require.NoError(t, rw.Create(ctx, u))

	at := &AuthToken{
		UserId: u.Id,
		Id:     "at_1234567890",
	}
	require.NoError(t, rw.Create(ctx, at))

	kt1 := &KeyringToken{
		KeyringType: "k1",
		TokenName:   "n1",
		AuthTokenId: at.Id,
	}
	require.NoError(t, rw.Create(ctx, kt1))
	kt2 := &KeyringToken{
		KeyringType: "k2",
		TokenName:   "n2",
		AuthTokenId: at.Id,
	}
	require.NoError(t, rw.Create(ctx, kt2))
	assert.NoError(t, rw.LookupById(ctx, u))

	// deleting the keyring tokens doesn't remove the user
	_, err = rw.Exec(ctx, "delete from keyring_token", nil)
	require.NoError(t, err)
	assert.NoError(t, rw.LookupById(ctx, at))
	assert.NoError(t, rw.LookupById(ctx, u))
}

func TestRefreshToken(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	rw := db.New(s)

	u := &user{
		Id:      "userId",
		Address: "address",
	}

	t.Run("no user foreign key constraint", func(t *testing.T) {
		tok := &refreshToken{
			UserId:       u.Id,
			ResourceType: targetResourceType,
			RefreshToken: "something",
		}
		require.ErrorContains(t, rw.Create(ctx, tok), "constraint failed")
	})

	require.NoError(t, rw.Create(ctx, u))

	t.Run("no user id", func(t *testing.T) {
		tok := &refreshToken{
			ResourceType: targetResourceType,
			RefreshToken: "something",
		}
		require.ErrorContains(t, rw.Create(ctx, tok), "constraint failed")
	})

	t.Run("unknown resource type", func(t *testing.T) {
		tok := &refreshToken{
			UserId:       u.Id,
			ResourceType: "thisisntknown",
			RefreshToken: "something",
		}
		require.ErrorContains(t, rw.Create(ctx, tok), "constraint failed")
	})

	t.Run("empty refresh token", func(t *testing.T) {
		tok := &refreshToken{
			UserId:       u.Id,
			ResourceType: "thisisntknown",
		}
		require.ErrorContains(t, rw.Create(ctx, tok), "constraint failed")
	})

	t.Run("create", func(t *testing.T) {
		tok := &refreshToken{
			UserId:       u.Id,
			ResourceType: targetResourceType,
			RefreshToken: "something",
		}
		before := time.Now().Truncate(1 * time.Millisecond)
		require.NoError(t, rw.Create(ctx, tok))
		require.NoError(t, rw.LookupById(ctx, tok))
		assert.GreaterOrEqual(t, tok.UpdateTime, before)
		assert.GreaterOrEqual(t, tok.CreateTime, before)
		assert.NotEmpty(t, tok.RefreshToken)
	})

	t.Run("update", func(t *testing.T) {
		u := &user{
			Id:      "updatethis",
			Address: "updated",
		}
		require.NoError(t, rw.Create(ctx, u))

		tok := &refreshToken{
			UserId:       u.Id,
			ResourceType: targetResourceType,
			RefreshToken: "started",
		}
		require.NoError(t, rw.Create(ctx, tok))

		tok.UpdateTime = time.Now().Add(-(24 * 365 * time.Hour))
		tok.RefreshToken = "updated"
		n, err := rw.Update(ctx, tok, []string{"UpdateTime", "RefreshToken"}, nil)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("delete user deletes token", func(t *testing.T) {
		u := &user{
			Id:      "deletethis",
			Address: "deleted",
		}
		require.NoError(t, rw.Create(ctx, u))

		tok := &refreshToken{
			UserId:       u.Id,
			ResourceType: targetResourceType,
			RefreshToken: "deleted_soon",
		}
		require.NoError(t, rw.Create(ctx, tok))

		_, err = rw.Exec(ctx, "delete from user where id = ?", []any{u.Id})

		require.True(t, errors.IsNotFoundError(rw.LookupById(ctx, tok)))
	})

	// TODO: When gorm sqlite driver fixes it's delete, use rw.Delete instead of the Exec.
	// n, err := rw.Delete(ctx, p)
	_, err = rw.Exec(ctx, "delete from refresh_token", nil)
	assert.NoError(t, err)
}

func TestAuthToken(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	rw := db.New(s)

	u := &user{
		Id:      "userId",
		Address: "address",
	}

	t.Run("no user foreign key constraint", func(t *testing.T) {
		tok := &AuthToken{
			UserId: u.Id,
			Id:     "at_1234567890",
		}
		require.ErrorContains(t, rw.Create(ctx, tok), "constraint failed")
	})

	require.NoError(t, rw.Create(ctx, u))

	t.Run("no user id", func(t *testing.T) {
		tok := &AuthToken{
			Id: "at_1234567890",
		}
		require.ErrorContains(t, rw.Create(ctx, tok), "constraint failed")
	})

	t.Run("create", func(t *testing.T) {
		tok := &AuthToken{
			UserId: u.Id,
			Id:     "at_create",
		}
		before := time.Now().Truncate(1 * time.Millisecond)
		require.NoError(t, rw.Create(ctx, tok))
		require.NoError(t, rw.LookupById(ctx, tok))
		assert.GreaterOrEqual(t, tok.LastAccessedTime, before)
	})

	t.Run("update", func(t *testing.T) {
		tok := &AuthToken{
			UserId: u.Id,
			Id:     "at_update",
		}
		require.NoError(t, rw.Create(ctx, tok))

		tok.LastAccessedTime = time.Now().Add(-(24 * 365 * time.Hour))
		n, err := rw.Update(ctx, tok, []string{"LastAccessedTime"}, nil)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("delete user deletes token", func(t *testing.T) {
		u := &user{
			Id:      "deletethis",
			Address: "deleted",
		}
		require.NoError(t, rw.Create(ctx, u))

		tok := &AuthToken{
			UserId: u.Id,
			Id:     "at_deleted",
		}
		require.NoError(t, rw.Create(ctx, tok))

		_, err = rw.Exec(ctx, "delete from user where id = ?", []any{u.Id})

		require.True(t, errors.IsNotFoundError(rw.LookupById(ctx, tok)))
	})

	// TODO: When gorm sqlite driver fixes it's delete, use rw.Delete instead of the Exec.
	// n, err := rw.Delete(ctx, p)
	_, err = rw.Exec(ctx, "delete from auth_token", nil)
	assert.NoError(t, err)
}

func TestKeyringToken(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)
	rw := db.New(s)

	u := &user{
		Id:      "userId",
		Address: "address",
	}
	require.NoError(t, rw.Create(ctx, u))

	at := &AuthToken{
		Id:     "at_1",
		UserId: u.Id,
	}

	t.Run("no token foreign key constraint", func(t *testing.T) {
		kt := &KeyringToken{
			KeyringType: "keyring",
			TokenName:   "token",
			AuthTokenId: at.Id,
		}
		require.ErrorContains(t, rw.Create(ctx, kt), "constraint failed")
	})

	require.NoError(t, rw.Create(ctx, at))

	t.Run("no auth token id", func(t *testing.T) {
		tok := &KeyringToken{
			KeyringType: "keyring",
			TokenName:   "token",
		}
		require.ErrorContains(t, rw.Create(ctx, tok), "constraint failed")
	})

	t.Run("create", func(t *testing.T) {
		kt := &KeyringToken{
			KeyringType: "keyring",
			TokenName:   "create",
			AuthTokenId: at.Id,
		}
		require.NoError(t, rw.Create(ctx, kt))
		require.NoError(t, rw.LookupById(ctx, kt))
	})

	t.Run("delete user deletes keyring token", func(t *testing.T) {
		u := &user{
			Id:      "deletethis",
			Address: "deleted",
		}
		require.NoError(t, rw.Create(ctx, u))

		at := &AuthToken{
			UserId: u.Id,
			Id:     "at_deleted",
		}
		require.NoError(t, rw.Create(ctx, at))

		kt := &KeyringToken{
			KeyringType: "keyring",
			TokenName:   "deleted",
			AuthTokenId: at.Id,
		}
		require.NoError(t, rw.Create(ctx, kt))
		require.NoError(t, rw.LookupById(ctx, kt))

		_, err = rw.Exec(ctx, "delete from user where id = ?", []any{u.Id})
		require.True(t, errors.IsNotFoundError(rw.LookupById(ctx, kt)))
	})

	t.Run("delete auth token deletes keyring token", func(t *testing.T) {
		u := &user{
			Id:      "deletethis",
			Address: "deleted",
		}
		require.NoError(t, rw.Create(ctx, u))

		at := &AuthToken{
			UserId: u.Id,
			Id:     "at_deleted",
		}
		require.NoError(t, rw.Create(ctx, at))

		kt := &KeyringToken{
			KeyringType: "keyring",
			TokenName:   "deleted",
			AuthTokenId: at.Id,
		}
		require.NoError(t, rw.Create(ctx, kt))
		require.NoError(t, rw.LookupById(ctx, kt))

		_, err = rw.Exec(ctx, "delete from auth_token where id = ?", []any{at.Id})
		require.True(t, errors.IsNotFoundError(rw.LookupById(ctx, kt)))
	})

	// TODO: When gorm sqlite driver fixes it's delete, use rw.Delete instead of the Exec.
	// n, err := rw.Delete(ctx, p)
	_, err = rw.Exec(ctx, "delete from keyring_token", nil)
	assert.NoError(t, err)
}

func TestTarget(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	rw := db.New(s)

	addr := "boundary"
	userId := "u_12345"
	u := &user{
		Id:      userId,
		Address: addr,
	}
	require.NoError(t, rw.Create(ctx, u))

	t.Run("target without user id", func(t *testing.T) {
		unknownTarget := &Target{
			Id:          "tssh_1234567890",
			Name:        "target",
			Description: "target desc",
			Address:     "some address",
			ScopeId:     "p_123",
			Type:        "tcp",
			Item:        "{id:'tssh_1234567890'}",
		}
		require.ErrorContains(t, rw.Create(ctx, unknownTarget), "constraint failed")
	})

	t.Run("target actions", func(t *testing.T) {
		target := &Target{
			FkUserId:    u.Id,
			Id:          "tssh_1234567890",
			Name:        "target",
			Description: "target desc",
			Address:     "some address",
			ScopeId:     "p_123",
			Type:        "tcp",
			Item:        "{id:'tssh_1234567890'}",
		}

		require.NoError(t, rw.Create(ctx, target))

		require.NoError(t, rw.LookupById(ctx, target))

		target.Address = "new address"
		n, err := rw.Update(ctx, target, []string{"address"}, nil)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)

		// TODO: Once the sqlite driver properly builds the delete query call
		// n, err = rw.Delete(ctx, target) instead of the Exec call
		n, err = rw.Exec(ctx, "delete from target where (fk_user_id, id) IN (values (?, ?))",
			[]any{target.FkUserId, target.Id})
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("lookup a target", func(t *testing.T) {
		target := &Target{
			FkUserId:    u.Id,
			Id:          "tssh_1234567890",
			Name:        "target",
			Description: "target desc",
			Address:     "some address",
			ScopeId:     "p_123",
			Type:        "tcp",
			Item:        "{id:'tssh_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, target))

		lookTar := &Target{
			FkUserId: target.FkUserId,
			Id:       target.Id,
		}
		assert.NoError(t, rw.LookupById(ctx, lookTar))
		assert.NotNil(t, lookTar)

		// cleanup the targets
		_, err := rw.Exec(ctx, "delete from target", nil)
		require.NoError(t, err)
	})

	t.Run("deleting the user deletes the target", func(t *testing.T) {
		target := &Target{
			FkUserId:    u.Id,
			Id:          "tssh_1234567890",
			Name:        "target",
			Description: "target desc",
			Address:     "some address",
			ScopeId:     "p_123",
			Type:        "tcp",
			Item:        "{id:'tssh_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, target))
		// Deleting the user deletes the target
		// TODO: Once the sqlite driver supports proper deletes change from the
		// Exec call to .Delete
		// n, err := rw.Delete(ctx, &u)
		n, err := rw.Exec(ctx, "delete from user where id = ?", []any{userId})
		require.NoError(t, err)
		require.Equal(t, 1, n)

		lookTar := &Target{
			FkUserId: target.FkUserId,
			Id:       target.Id,
		}
		assert.ErrorContains(t, rw.LookupById(ctx, lookTar), "not found")
	})
}

func TestSession(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	rw := db.New(s)

	addr := "boundary"
	userId := "u_12345"
	u := &user{
		Id:      userId,
		Address: addr,
	}
	require.NoError(t, rw.Create(ctx, u))

	t.Run("session without user id", func(t *testing.T) {
		unknownSess := &Session{
			Id:   "sess_1234567890",
			Item: "{id:'sess_1234567890'}",
		}
		require.ErrorContains(t, rw.Create(ctx, unknownSess), "FOREIGN KEY constraint")
	})
	t.Run("session actions", func(t *testing.T) {
		session := &Session{
			FkUserId: u.Id,
			Id:       "s_1234567890",
			Endpoint: "endpoint",
			ScopeId:  "p_123",
			TargetId: "ttcp_123",
			UserId:   "u_123",
			Item:     "{id:'s_1234567890'}",
		}

		require.NoError(t, rw.Create(ctx, session))

		require.NoError(t, rw.LookupById(ctx, session))

		session.Endpoint = "new endpoint"
		n, err := rw.Update(ctx, session, []string{"endpoint"}, nil)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)

		// TODO: Once the sqlite driver properly builds the delete query call
		// n, err = rw.Delete(ctx, session) instead of the Exec call
		n, err = rw.Exec(ctx, "delete from session where (fk_user_id, id) IN (values (?, ?))",
			[]any{session.FkUserId, session.Id})
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("lookup a session", func(t *testing.T) {
		session := &Session{
			FkUserId: u.Id,
			Id:       "s_1234567890",
			Endpoint: "endpoint",
			ScopeId:  "p_123",
			TargetId: "ttcp_123",
			UserId:   "u_123",
			Item:     "{id:'s_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, session))

		lookSess := &Session{
			FkUserId: u.Id,
			Id:       session.Id,
		}
		assert.NoError(t, rw.LookupById(ctx, lookSess))
		assert.NotNil(t, lookSess)

		// cleanup the sessions
		_, err := rw.Exec(ctx, "delete from session", nil)
		require.NoError(t, err)
	})

	t.Run("deleting the user deletes the session", func(t *testing.T) {
		session := &Session{
			FkUserId: u.Id,
			Id:       "s_1234567890",
			Endpoint: "endpoint",
			ScopeId:  "p_123",
			TargetId: "ttcp_123",
			UserId:   "u_123",
			Item:     "{id:'s_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, session))
		// Deleting the user deletes the session
		// TODO: Once the sqlite driver supports proper deletes change from the
		// Exec call to .Delete
		// n, err := rw.Delete(ctx, &u)
		n, err := rw.Exec(ctx, "delete from user where id = ?", []any{userId})
		require.NoError(t, err)
		require.Equal(t, 1, n)

		lookSess := &Session{
			FkUserId: session.FkUserId,
			Id:       session.Id,
		}
		assert.ErrorContains(t, rw.LookupById(ctx, lookSess), "not found")
	})
}

func TestRepository_SqliteReadDuringTx(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)
	rw := db.New(s)

	ret := AuthToken{
		Id: "something",
	}
	assert.ErrorContains(t, rw.LookupById(ctx, &ret), "not found")

	var startTx sync.WaitGroup
	startTx.Add(1)
	go func() {
		_, err = rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, writer db.Writer) error {
			startTx.Done()
			time.Sleep(500 * time.Millisecond)

			assert.ErrorContains(t, reader.LookupById(ctx, &ret), "not found")
			return nil
		})
	}()
	// setup a read that potentially executes during a tx
	startTx.Wait()
	assert.ErrorContains(t, rw.LookupById(ctx, &ret), "not found")
}
