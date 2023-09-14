// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPersona(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	rw := db.New(s.conn)
	addr := "boundary"
	userId := "u_12345"
	p := Persona{
		BoundaryAddr: addr,
		UserId:       userId,
		KeyringType:  "keyring",
		TokenName:    "default",
		AuthTokenId:  "at_1234567890",
	}
	before := time.Now().Truncate(1 * time.Millisecond)
	require.NoError(t, rw.Create(ctx, &p))

	require.NoError(t, rw.LookupById(ctx, &p))
	assert.GreaterOrEqual(t, p.LastAccessedTime, before)

	p.AuthTokenId = "at_0987654321"
	n, err := rw.Update(ctx, &p, []string{"AuthTokenId"}, nil)
	assert.NoError(t, err)
	assert.Equal(t, 1, n)

	// TODO: When gorm sqlite driver fixes it's delete, use rw.Delete instead of the Exec.
	// n, err := rw.Delete(ctx, p)
	n, err = rw.Exec(ctx, "delete from cache_persona where (boundary_addr, keyring_type, token_name) in (values (?, ?, ?))",
		[]any{p.BoundaryAddr, p.KeyringType, p.TokenName})
	assert.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestTarget(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	rw := db.New(s.conn)

	keyringType := "keyring"
	tokenName := "token"
	addr := "boundary"
	userId := "u_12345"
	p := &Persona{
		KeyringType:  keyringType,
		TokenName:    tokenName,
		BoundaryAddr: addr,
		UserId:       userId,
		AuthTokenId:  "at_1234567890",
	}
	require.NoError(t, rw.Create(ctx, p))

	t.Run("target without user id", func(t *testing.T) {
		unknownTarget := &Target{
			KeyringType:  p.KeyringType,
			TokenName:    p.TokenName,
			BoundaryAddr: "some unknown addr",
			Id:           "tssh_1234567890",
			Name:         "target",
			Description:  "target desc",
			Address:      "some address",
			Item:         "{id:'tssh_1234567890'}",
		}
		require.ErrorContains(t, rw.Create(ctx, unknownTarget), "FOREIGN KEY constraint")
	})
	t.Run("target without keyring type", func(t *testing.T) {
		unknownTarget := &Target{
			TokenName:      p.TokenName,
			BoundaryUserId: p.UserId,
			BoundaryAddr:   "some unknown addr",
			Id:             "tssh_1234567890",
			Name:           "target",
			Description:    "target desc",
			Address:        "some address",
			Item:           "{id:'tssh_1234567890'}",
		}
		require.ErrorContains(t, rw.Create(ctx, unknownTarget), "FOREIGN KEY constraint")
	})
	t.Run("target without token name", func(t *testing.T) {
		unknownTarget := &Target{
			KeyringType:    p.KeyringType,
			BoundaryUserId: p.UserId,
			BoundaryAddr:   "some unknown addr",
			Id:             "tssh_1234567890",
			Name:           "target",
			Description:    "target desc",
			Address:        "some address",
			Item:           "{id:'tssh_1234567890'}",
		}
		require.ErrorContains(t, rw.Create(ctx, unknownTarget), "FOREIGN KEY constraint")
	})

	t.Run("target actions", func(t *testing.T) {
		target := &Target{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   p.BoundaryAddr,
			BoundaryUserId: p.UserId,
			Id:             "tssh_1234567890",
			Name:           "target",
			Description:    "target desc",
			Address:        "some address",
			Item:           "{id:'tssh_1234567890'}",
		}

		require.NoError(t, rw.Create(ctx, target))

		require.NoError(t, rw.LookupById(ctx, target))

		target.Address = "new address"
		n, err := rw.Update(ctx, target, []string{"address"}, nil)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)

		// TODO: Once the sqlite driver properly builds the delete query call
		// n, err = rw.Delete(ctx, target) instead of the Exec call
		n, err = rw.Exec(ctx, "delete from cache_target where (boundary_addr, boundary_user_id, id) IN (values (?, ?, ?))",
			[]any{target.BoundaryAddr, target.BoundaryUserId, target.Id})
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("lookup a target", func(t *testing.T) {
		target := &Target{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   p.BoundaryAddr,
			BoundaryUserId: p.UserId,
			Id:             "tssh_1234567890",
			Name:           "target",
			Description:    "target desc",
			Address:        "some address",
			Item:           "{id:'tssh_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, target))

		lookTar := &Target{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   target.BoundaryAddr,
			BoundaryUserId: p.UserId,
			Id:             target.Id,
		}
		assert.NoError(t, rw.LookupById(ctx, lookTar))
		assert.NotNil(t, lookTar)

		// cleanup the targets
		_, err := rw.Exec(ctx, "delete from cache_target", nil)
		require.NoError(t, err)
	})

	t.Run("deleting the persona deletes the target", func(t *testing.T) {
		target := &Target{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   p.BoundaryAddr,
			BoundaryUserId: p.UserId,
			Id:             "tssh_1234567890",
			Name:           "target",
			Description:    "target desc",
			Address:        "some address",
			Item:           "{id:'tssh_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, target))
		// Deleting the user deletes the target
		// TODO: Once the sqlite driver supports proper deletes change from the
		// Exec call to .Delete
		// n, err := rw.Delete(ctx, &u)
		n, err := rw.Exec(ctx, "delete from cache_persona where (keyring_type, token_name, boundary_addr, user_id) IN (values (?, ?, ?, ?))",
			[]any{p.KeyringType, p.TokenName, p.BoundaryAddr, userId})
		require.NoError(t, err)
		require.Equal(t, 1, n)

		lookTar := &Target{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   target.BoundaryAddr,
			BoundaryUserId: target.BoundaryUserId,
			Id:             target.Id,
		}
		assert.ErrorContains(t, rw.LookupById(ctx, lookTar), "not found")
	})

	t.Run("changing the personas user id deletes the target", func(t *testing.T) {
		// Ensure that the trigger executes with an on conflict update
		personaOnConflict := &db.OnConflict{
			Target: db.Columns{"keyring_type", "token_name"},
			Action: db.SetColumns([]string{"auth_token_id", "boundary_addr", "user_id", "last_accessed_time"}),
		}
		p := &Persona{
			KeyringType:  keyringType,
			TokenName:    tokenName,
			BoundaryAddr: addr,
			UserId:       userId,
			AuthTokenId:  "at_1234567890",
		}
		require.NoError(t, rw.Create(ctx, p, db.WithOnConflict(personaOnConflict)))

		target := &Target{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   p.BoundaryAddr,
			BoundaryUserId: p.UserId,
			Id:             "tssh_1234567890",
			Name:           "target",
			Description:    "target desc",
			Address:        "some address",
			Item:           "{id:'tssh_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, target))

		newPersona := p.clone()
		newPersona.UserId = "A New Id"
		require.NoError(t, rw.Create(ctx, newPersona, db.WithOnConflict(personaOnConflict)))

		lookTar := &Target{
			KeyringType:    target.KeyringType,
			TokenName:      target.TokenName,
			BoundaryAddr:   target.BoundaryAddr,
			BoundaryUserId: target.BoundaryUserId,
			Id:             target.Id,
		}
		require.ErrorContains(t, rw.LookupById(ctx, lookTar), "not found")
	})

	t.Run("changing the personas address deletes the target", func(t *testing.T) {
		// Ensure that the trigger executes with an on conflict update
		personaOnConflict := &db.OnConflict{
			Target: db.Columns{"keyring_type", "token_name"},
			Action: db.SetColumns([]string{"auth_token_id", "boundary_addr", "user_id", "last_accessed_time"}),
		}
		p := &Persona{
			KeyringType:  keyringType,
			TokenName:    tokenName,
			BoundaryAddr: addr,
			UserId:       userId,
			AuthTokenId:  "at_1234567890",
		}
		require.NoError(t, rw.Create(ctx, p, db.WithOnConflict(personaOnConflict)))

		target := &Target{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   p.BoundaryAddr,
			BoundaryUserId: p.UserId,
			Id:             "tssh_1234567890",
			Name:           "target",
			Description:    "target desc",
			Address:        "some address",
			Item:           "{id:'tssh_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, target))

		newPersona := p.clone()
		newPersona.BoundaryAddr = "a.new.address"
		require.NoError(t, rw.Create(ctx, newPersona, db.WithOnConflict(personaOnConflict)))

		lookTar := &Target{
			KeyringType:    target.KeyringType,
			TokenName:      target.TokenName,
			BoundaryAddr:   target.BoundaryAddr,
			BoundaryUserId: target.BoundaryUserId,
			Id:             target.Id,
		}
		require.ErrorContains(t, rw.LookupById(ctx, lookTar), "not found")
	})

	t.Run("changing the personas token id doesnt delete the target", func(t *testing.T) {
		// Ensure that the trigger executes with an on conflict update
		personaOnConflict := &db.OnConflict{
			Target: db.Columns{"keyring_type", "token_name"},
			Action: db.SetColumns([]string{"auth_token_id", "boundary_addr", "user_id", "last_accessed_time"}),
		}
		p := &Persona{
			KeyringType:  keyringType,
			TokenName:    tokenName,
			BoundaryAddr: addr,
			UserId:       userId,
			AuthTokenId:  "at_1234567890",
		}
		require.NoError(t, rw.Create(ctx, p, db.WithOnConflict(personaOnConflict)))

		target := &Target{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   p.BoundaryAddr,
			BoundaryUserId: p.UserId,
			Id:             "tssh_1234567890",
			Name:           "target",
			Description:    "target desc",
			Address:        "some address",
			Item:           "{id:'tssh_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, target))

		newPersona := p.clone()
		newPersona.AuthTokenId = "A New Id"
		require.NoError(t, rw.Create(ctx, newPersona, db.WithOnConflict(personaOnConflict)))

		lookTar := &Target{
			KeyringType:    target.KeyringType,
			TokenName:      target.TokenName,
			BoundaryAddr:   target.BoundaryAddr,
			BoundaryUserId: target.BoundaryUserId,
			Id:             target.Id,
		}
		require.NoError(t, rw.LookupById(ctx, lookTar))

		// cleanup the targets
		_, err := rw.Exec(ctx, "delete from cache_target", nil)
		require.NoError(t, err)
	})
}

func TestSession(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	rw := db.New(s.conn)

	keyringType := "keyring"
	tokenName := "token"
	addr := "boundary"
	userId := "u_12345"
	p := &Persona{
		KeyringType:  keyringType,
		TokenName:    tokenName,
		BoundaryAddr: addr,
		UserId:       userId,
		AuthTokenId:  "at_1234567890",
	}
	require.NoError(t, rw.Create(ctx, p))

	t.Run("session without user id", func(t *testing.T) {
		unknownSess := &Session{
			KeyringType:  p.KeyringType,
			TokenName:    p.TokenName,
			BoundaryAddr: "some unknown addr",
			Id:           "sess_1234567890",
			Item:         "{id:'sess_1234567890'}",
		}
		require.ErrorContains(t, rw.Create(ctx, unknownSess), "FOREIGN KEY constraint")
	})
	t.Run("session without keyring type", func(t *testing.T) {
		unknownSession := &Session{
			TokenName:      p.TokenName,
			BoundaryUserId: p.UserId,
			BoundaryAddr:   "some unknown addr",
			Id:             "s_1234567890",
			Item:           "{id:'s_1234567890'}",
		}
		require.ErrorContains(t, rw.Create(ctx, unknownSession), "FOREIGN KEY constraint")
	})
	t.Run("session without token name", func(t *testing.T) {
		unknownSession := &Session{
			KeyringType:    p.KeyringType,
			BoundaryUserId: p.UserId,
			BoundaryAddr:   "some unknown addr",
			Id:             "s_1234567890",
			Item:           "{id:'s_1234567890'}",
		}
		require.ErrorContains(t, rw.Create(ctx, unknownSession), "FOREIGN KEY constraint")
	})

	t.Run("session actions", func(t *testing.T) {
		session := &Session{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   p.BoundaryAddr,
			BoundaryUserId: p.UserId,
			Id:             "s_1234567890",
			Endpoint:       "endpoint",
			Item:           "{id:'s_1234567890'}",
		}

		require.NoError(t, rw.Create(ctx, session))

		require.NoError(t, rw.LookupById(ctx, session))

		session.Endpoint = "new endpoint"
		n, err := rw.Update(ctx, session, []string{"endpoint"}, nil)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)

		// TODO: Once the sqlite driver properly builds the delete query call
		// n, err = rw.Delete(ctx, session) instead of the Exec call
		n, err = rw.Exec(ctx, "delete from cache_session where (boundary_addr, boundary_user_id, id) IN (values (?, ?, ?))",
			[]any{session.BoundaryAddr, session.BoundaryUserId, session.Id})
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("lookup a session", func(t *testing.T) {
		session := &Session{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   p.BoundaryAddr,
			BoundaryUserId: p.UserId,
			Id:             "s_1234567890",
			Endpoint:       "endpoint",
			Item:           "{id:'s_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, session))

		lookSess := &Session{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   session.BoundaryAddr,
			BoundaryUserId: p.UserId,
			Id:             session.Id,
		}
		assert.NoError(t, rw.LookupById(ctx, lookSess))
		assert.NotNil(t, lookSess)

		// cleanup the sessions
		_, err := rw.Exec(ctx, "delete from cache_session", nil)
		require.NoError(t, err)
	})

	t.Run("deleting the persona deletes the session", func(t *testing.T) {
		session := &Session{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   p.BoundaryAddr,
			BoundaryUserId: p.UserId,
			Id:             "s_1234567890",
			Endpoint:       "endpoint",
			Item:           "{id:'s_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, session))
		// Deleting the user deletes the session
		// TODO: Once the sqlite driver supports proper deletes change from the
		// Exec call to .Delete
		// n, err := rw.Delete(ctx, &u)
		n, err := rw.Exec(ctx, "delete from cache_persona where (keyring_type, token_name, boundary_addr, user_id) IN (values (?, ?, ?, ?))",
			[]any{p.KeyringType, p.TokenName, p.BoundaryAddr, userId})
		require.NoError(t, err)
		require.Equal(t, 1, n)

		lookSess := &Session{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   session.BoundaryAddr,
			BoundaryUserId: session.BoundaryUserId,
			Id:             session.Id,
		}
		assert.ErrorContains(t, rw.LookupById(ctx, lookSess), "not found")
	})

	t.Run("changing the personas user id deletes the session", func(t *testing.T) {
		// Ensure that the trigger executes with an on conflict update
		personaOnConflict := &db.OnConflict{
			Target: db.Columns{"keyring_type", "token_name"},
			Action: db.SetColumns([]string{"auth_token_id", "boundary_addr", "user_id", "last_accessed_time"}),
		}
		p := &Persona{
			KeyringType:  keyringType,
			TokenName:    tokenName,
			BoundaryAddr: addr,
			UserId:       userId,
			AuthTokenId:  "at_1234567890",
		}
		require.NoError(t, rw.Create(ctx, p, db.WithOnConflict(personaOnConflict)))

		session := &Session{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   p.BoundaryAddr,
			BoundaryUserId: p.UserId,
			Id:             "s_1234567890",
			Item:           "{id:'s_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, session))

		newPersona := p.clone()
		newPersona.UserId = "A New Id"
		require.NoError(t, rw.Create(ctx, newPersona, db.WithOnConflict(personaOnConflict)))

		lookSess := &Session{
			KeyringType:    session.KeyringType,
			TokenName:      session.TokenName,
			BoundaryAddr:   session.BoundaryAddr,
			BoundaryUserId: session.BoundaryUserId,
			Id:             session.Id,
		}
		require.ErrorContains(t, rw.LookupById(ctx, lookSess), "not found")
	})

	t.Run("changing the personas address deletes the session", func(t *testing.T) {
		// Ensure that the trigger executes with an on conflict update
		personaOnConflict := &db.OnConflict{
			Target: db.Columns{"keyring_type", "token_name"},
			Action: db.SetColumns([]string{"auth_token_id", "boundary_addr", "user_id", "last_accessed_time"}),
		}
		p := &Persona{
			KeyringType:  keyringType,
			TokenName:    tokenName,
			BoundaryAddr: addr,
			UserId:       userId,
			AuthTokenId:  "at_1234567890",
		}
		require.NoError(t, rw.Create(ctx, p, db.WithOnConflict(personaOnConflict)))

		session := &Session{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   p.BoundaryAddr,
			BoundaryUserId: p.UserId,
			Id:             "s_1234567890",
			Item:           "{id:'s_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, session))

		newPersona := p.clone()
		newPersona.BoundaryAddr = "a.new.address"
		require.NoError(t, rw.Create(ctx, newPersona, db.WithOnConflict(personaOnConflict)))

		lookSess := &Session{
			KeyringType:    session.KeyringType,
			TokenName:      session.TokenName,
			BoundaryAddr:   session.BoundaryAddr,
			BoundaryUserId: session.BoundaryUserId,
			Id:             session.Id,
		}
		require.ErrorContains(t, rw.LookupById(ctx, lookSess), "not found")
	})

	t.Run("changing the personas token id doesnt delete the session", func(t *testing.T) {
		// Ensure that the trigger executes with an on conflict update
		personaOnConflict := &db.OnConflict{
			Target: db.Columns{"keyring_type", "token_name"},
			Action: db.SetColumns([]string{"auth_token_id", "boundary_addr", "user_id", "last_accessed_time"}),
		}
		p := &Persona{
			KeyringType:  keyringType,
			TokenName:    tokenName,
			BoundaryAddr: addr,
			UserId:       userId,
			AuthTokenId:  "at_1234567890",
		}
		require.NoError(t, rw.Create(ctx, p, db.WithOnConflict(personaOnConflict)))

		session := &Session{
			KeyringType:    p.KeyringType,
			TokenName:      p.TokenName,
			BoundaryAddr:   p.BoundaryAddr,
			BoundaryUserId: p.UserId,
			Id:             "s_1234567890",
			Item:           "{id:'s_1234567890'}",
		}
		require.NoError(t, rw.Create(ctx, session))

		newPersona := p.clone()
		newPersona.AuthTokenId = "A New Id"
		require.NoError(t, rw.Create(ctx, newPersona, db.WithOnConflict(personaOnConflict)))

		lookSess := &Session{
			KeyringType:    session.KeyringType,
			TokenName:      session.TokenName,
			BoundaryAddr:   session.BoundaryAddr,
			BoundaryUserId: session.BoundaryUserId,
			Id:             session.Id,
		}
		require.NoError(t, rw.LookupById(ctx, lookSess))

		// cleanup the sessions
		_, err := rw.Exec(ctx, "delete from cache_session", nil)
		require.NoError(t, err)
	})
}
