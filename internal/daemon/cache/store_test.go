// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
	s, err := Open(ctx, WithDebug(true))
	require.NoError(t, err)

	rw := db.New(s.conn)

	p := Persona{
		BoundaryAddr: "boundary",
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

	n, err = rw.Delete(ctx, &p)
	assert.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestTarget(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, WithDebug(true))
	require.NoError(t, err)

	rw := db.New(s.conn)

	p := &Persona{
		BoundaryAddr: "boundary",
		KeyringType:  "keyring",
		TokenName:    "default",
		AuthTokenId:  "at_1234567890",
	}
	require.NoError(t, rw.Create(ctx, p))

	t.Run("target without persona", func(t *testing.T) {
		unknownTarget := &Target{
			BoundaryAddr: "some unknown addr",
			TokenName:    "some token name",
			Id:           "tssh_1234567890",
			Name:         "target",
			Description:  "target desc",
			Address:      "some address",
			Item:         "{id:'tssh_1234567890'}",
		}
		require.ErrorContains(t, rw.Create(ctx, unknownTarget), "FOREIGN KEY constraint")
	})

	t.Run("target actions", func(t *testing.T) {
		target := &Target{
			BoundaryAddr: p.BoundaryAddr,
			KeyringType:  p.KeyringType,
			TokenName:    p.TokenName,
			Id:           "tssh_1234567890",
			Name:         "target",
			Description:  "target desc",
			Address:      "some address",
			Item:         "{id:'tssh_1234567890'}",
		}

		require.NoError(t, rw.Create(ctx, target))

		require.NoError(t, rw.LookupById(ctx, target))

		target.Address = "new address"
		n, err := rw.Update(ctx, target, []string{"address"}, nil)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)

		n, err = rw.Delete(ctx, target)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	target := &Target{
		BoundaryAddr: p.BoundaryAddr,
		TokenName:    p.TokenName,
		KeyringType:  p.KeyringType,
		Id:           "tssh_1234567890",
		Name:         "target",
		Description:  "target desc",
		Address:      "some address",
		Item:         "{id:'tssh_1234567890'}",
	}
	require.NoError(t, rw.Create(ctx, target))

	t.Run("lookup a target", func(t *testing.T) {
		lookTar := &Target{
			BoundaryAddr: target.BoundaryAddr,
			TokenName:    target.TokenName,
			KeyringType:  target.KeyringType,
			Id:           target.Id,
		}
		assert.NoError(t, rw.LookupById(ctx, lookTar))
		assert.NotNil(t, lookTar)
	})

	t.Run("deleting the persona deletes the target", func(t *testing.T) {
		n, err := rw.Delete(ctx, p)
		require.NoError(t, err)
		require.Equal(t, 1, n)

		lookTar := &Target{
			BoundaryAddr: target.BoundaryAddr,
			TokenName:    target.TokenName,
			KeyringType:  target.KeyringType,
			Id:           target.Id,
		}
		assert.ErrorContains(t, rw.LookupById(ctx, lookTar), "not found")
	})
}
