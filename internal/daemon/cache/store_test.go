// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUser(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)
	rw := db.New(s.conn)

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
	s, err := Open(ctx)
	require.NoError(t, err)
	rw := db.New(s.conn)

	u := &user{
		Id:      "userId",
		Address: "address",
	}
	require.NoError(t, rw.Create(ctx, u))

	tok1 := &Token{
		UserId:      u.Id,
		KeyringType: "first",
		TokenName:   "first",
		AuthTokenId: "at_1234567890",
	}
	require.NoError(t, rw.Create(ctx, tok1))
	tok2 := &Token{
		UserId:      u.Id,
		KeyringType: "second",
		TokenName:   "second",
		AuthTokenId: "at_1234567890",
	}
	require.NoError(t, rw.Create(ctx, tok2))
	assert.NoError(t, rw.LookupById(ctx, u))

	// deleting a single token doesn't remove the user
	_, err = rw.Exec(ctx, "delete from token where (keyring_type, token_name) = (?, ?)", []any{tok1.KeyringType, tok1.TokenName})
	require.NoError(t, err)
	assert.NoError(t, rw.LookupById(ctx, u))

	// deleting both tokens _does_ remove the user
	_, err = rw.Exec(ctx, "delete from token", nil)
	require.NoError(t, err)
	assert.True(t, errors.IsNotFoundError(rw.LookupById(ctx, u)))
}

func TestToken(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	rw := db.New(s.conn)

	u := &user{
		Id:      "userId",
		Address: "address",
	}

	t.Run("no user foreign key constraint", func(t *testing.T) {
		tok := &Token{
			UserId:      u.Id,
			KeyringType: "keyring",
			TokenName:   "default",
			AuthTokenId: "at_1234567890",
		}
		require.ErrorContains(t, rw.Create(ctx, tok), "constraint failed")
	})

	require.NoError(t, rw.Create(ctx, u))
	t.Run("missing auth token id", func(t *testing.T) {
		tok := &Token{
			UserId:      u.Id,
			KeyringType: "keyring",
			TokenName:   "default",
		}
		require.ErrorContains(t, rw.Create(ctx, tok), "constraint failed")
	})

	t.Run("no user id", func(t *testing.T) {
		tok := &Token{
			KeyringType: "keyring",
			TokenName:   "default",
			AuthTokenId: "at_1234567890",
		}
		require.ErrorContains(t, rw.Create(ctx, tok), "constraint failed")
	})

	t.Run("create", func(t *testing.T) {
		tok := &Token{
			UserId:      u.Id,
			KeyringType: "keyring",
			TokenName:   "default",
			AuthTokenId: "at_1234567890",
		}
		before := time.Now().Truncate(1 * time.Millisecond)
		require.NoError(t, rw.Create(ctx, tok))
		require.NoError(t, rw.LookupById(ctx, tok))
		assert.GreaterOrEqual(t, tok.LastAccessedTime, before)
	})

	t.Run("update", func(t *testing.T) {
		tok := &Token{
			UserId:      u.Id,
			KeyringType: "updated",
			TokenName:   "default",
			AuthTokenId: "at_1234567890",
		}
		require.NoError(t, rw.Create(ctx, tok))

		tok.AuthTokenId = "at_0987654321"
		n, err := rw.Update(ctx, tok, []string{"AuthTokenId"}, nil)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("delete user deletes token", func(t *testing.T) {
		u := &user{
			Id:      "deletethis",
			Address: "deleted",
		}
		require.NoError(t, rw.Create(ctx, u))

		tok := &Token{
			UserId:      u.Id,
			KeyringType: "deleteuser",
			TokenName:   "default",
			AuthTokenId: "at_1234567890",
		}
		require.NoError(t, rw.Create(ctx, tok))

		_, err = rw.Exec(ctx, "delete from user where id = ?", []any{u.Id})

		require.True(t, errors.IsNotFoundError(rw.LookupById(ctx, tok)))
	})

	// TODO: When gorm sqlite driver fixes it's delete, use rw.Delete instead of the Exec.
	// n, err := rw.Delete(ctx, p)
	_, err = rw.Exec(ctx, "delete from token", nil)
	assert.NoError(t, err)
}

func TestTarget(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	rw := db.New(s.conn)

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
			Item:        "{id:'tssh_1234567890'}",
		}
		require.ErrorContains(t, rw.Create(ctx, unknownTarget), "constraint failed")
	})

	t.Run("target actions", func(t *testing.T) {
		target := &Target{
			UserId:      u.Id,
			Id:          "tssh_1234567890",
			Name:        "target",
			Description: "target desc",
			Address:     "some address",
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
		n, err = rw.Exec(ctx, "delete from target where (user_id, id) IN (values (?, ?))",
			[]any{target.UserId, target.Id})
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("lookup a target", func(t *testing.T) {
		target := &Target{
			UserId:      u.Id,
			Id:          "tssh_1234567890",
			Name:        "target",
			Description: "target desc",
			Address:     "some address",
			Item:        "{id:'tssh_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, target))

		lookTar := &Target{
			UserId: target.UserId,
			Id:     target.Id,
		}
		assert.NoError(t, rw.LookupById(ctx, lookTar))
		assert.NotNil(t, lookTar)

		// cleanup the targets
		_, err := rw.Exec(ctx, "delete from target", nil)
		require.NoError(t, err)
	})

	t.Run("deleting the user deletes the target", func(t *testing.T) {
		target := &Target{
			UserId:      u.Id,
			Id:          "tssh_1234567890",
			Name:        "target",
			Description: "target desc",
			Address:     "some address",
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
			UserId: target.UserId,
			Id:     target.Id,
		}
		assert.ErrorContains(t, rw.LookupById(ctx, lookTar), "not found")
	})
}

func TestSession(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	rw := db.New(s.conn)

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
			UserId:   u.Id,
			Id:       "s_1234567890",
			Endpoint: "endpoint",
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
		n, err = rw.Exec(ctx, "delete from session where (user_id, id) IN (values (?, ?))",
			[]any{session.UserId, session.Id})
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("lookup a session", func(t *testing.T) {
		session := &Session{
			UserId:   u.Id,
			Id:       "s_1234567890",
			Endpoint: "endpoint",
			Item:     "{id:'s_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, session))

		lookSess := &Session{
			UserId: u.Id,
			Id:     session.Id,
		}
		assert.NoError(t, rw.LookupById(ctx, lookSess))
		assert.NotNil(t, lookSess)

		// cleanup the sessions
		_, err := rw.Exec(ctx, "delete from session", nil)
		require.NoError(t, err)
	})

	t.Run("deleting the persona deletes the session", func(t *testing.T) {
		session := &Session{
			UserId:   u.Id,
			Id:       "s_1234567890",
			Endpoint: "endpoint",
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
			UserId: session.UserId,
			Id:     session.Id,
		}
		assert.ErrorContains(t, rw.LookupById(ctx, lookSess), "not found")
	})
}
