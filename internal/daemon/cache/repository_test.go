// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_AddPersona_EvictsOverLimit(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s)
	require.NoError(t, err)

	addr := "address"
	p := &Persona{
		BoundaryAddr: addr,
		TokenName:    "default",
		KeyringType:  "keyring",
		AuthTokenId:  "at_1234567890",
	}
	assert.NoError(t, r.AddPersona(ctx, p))
	assert.NoError(t, r.AddPersona(ctx, p))
	for i := 0; i < personaLimit; i++ {
		p.BoundaryAddr = fmt.Sprintf("%s%d", addr, i)
		assert.NoError(t, r.AddPersona(ctx, p))
	}
	// Lookup the first persona added. It should have been evicted for being
	// used the least recently.
	gotP, err := r.LookupPersona(ctx, addr, p.KeyringType, p.TokenName)
	assert.NoError(t, err)
	assert.Nil(t, gotP)

	p, err = r.LookupPersona(ctx, addr+"0", p.KeyringType, p.TokenName)
	assert.NoError(t, err)
	assert.NotNil(t, p)
}

func TestRepository_AddPersona_AddingExistingUpdatesLastAccessedTime(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s)
	require.NoError(t, err)

	p1 := &Persona{
		BoundaryAddr: "address",
		TokenName:    "default",
		KeyringType:  "keyring",
		AuthTokenId:  "at_1234567890",
	}
	assert.NoError(t, r.AddPersona(ctx, p1))
	p2 := p1.clone()
	p2.BoundaryAddr = "address2"
	assert.NoError(t, r.AddPersona(ctx, p2))

	time.Sleep(10 * time.Millisecond)
	assert.NoError(t, r.AddPersona(ctx, p1))

	gotP1, err := r.LookupPersona(ctx, p1.BoundaryAddr, p1.KeyringType, p1.TokenName)
	require.NoError(t, err)
	gotP2, err := r.LookupPersona(ctx, p2.BoundaryAddr, p2.KeyringType, p2.TokenName)
	require.NoError(t, err)

	assert.Greater(t, gotP1.LastAccessedTime, gotP2.LastAccessedTime)
}

func TestRepository_ListPersonas(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s)
	require.NoError(t, err)

	t.Run("no personas", func(t *testing.T) {
		gotP, err := r.ListPersonas(ctx)
		assert.NoError(t, err)
		assert.Empty(t, gotP)
	})

	personaCount := 15
	addr := "address"
	p := &Persona{
		BoundaryAddr: addr,
		TokenName:    "default",
		KeyringType:  "keyring",
		AuthTokenId:  "at_1234567890",
	}
	for i := 0; i < personaCount; i++ {
		p.BoundaryAddr = fmt.Sprintf("%s%d", addr, i)
		require.NoError(t, r.AddPersona(ctx, p))
	}

	t.Run("many personas", func(t *testing.T) {
		gotP, err := r.ListPersonas(ctx)
		assert.NoError(t, err)
		assert.Len(t, gotP, personaCount)
	})
}

func TestRepository_DeletePersona(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s)
	require.NoError(t, err)

	t.Run("delete non existing", func(t *testing.T) {
		assert.ErrorContains(t, r.DeletePersona(ctx, &Persona{BoundaryAddr: "unknown", KeyringType: "Unknown", TokenName: "Unknown"}), "not found")
	})

	t.Run("delete existing", func(t *testing.T) {
		p := &Persona{
			BoundaryAddr: "some address",
			TokenName:    "default",
			KeyringType:  "keyring",
			AuthTokenId:  "at_1234567890",
		}
		assert.NoError(t, r.AddPersona(ctx, p))
		gotP, err := r.LookupPersona(ctx, p.BoundaryAddr, p.KeyringType, p.TokenName)
		require.NoError(t, err)
		require.NotNil(t, gotP)

		assert.NoError(t, r.DeletePersona(ctx, p))

		gotP, err = r.LookupPersona(ctx, p.BoundaryAddr, p.KeyringType, p.TokenName)
		require.NoError(t, err)
		require.Nil(t, gotP)
	})
}

func TestRepository_LookupPersona(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s)
	require.NoError(t, err)

	t.Run("empty address", func(t *testing.T) {
		p, err := r.LookupPersona(ctx, "", "keyring", "token")
		assert.ErrorContains(t, err, "address is empty")
		assert.Nil(t, p)
	})
	t.Run("empty token name", func(t *testing.T) {
		p, err := r.LookupPersona(ctx, "address", "keyring", "")
		assert.ErrorContains(t, err, "token name is empty")
		assert.Nil(t, p)
	})
	t.Run("empty keyring type", func(t *testing.T) {
		p, err := r.LookupPersona(ctx, "address", "", "token")
		assert.ErrorContains(t, err, "keyring type is empty")
		assert.Nil(t, p)
	})
	t.Run("not found", func(t *testing.T) {
		p, err := r.LookupPersona(ctx, "address", "keyring", "token")
		assert.NoError(t, err)
		assert.Nil(t, p)
	})
	t.Run("found", func(t *testing.T) {
		addr := "address"
		p := &Persona{
			BoundaryAddr: addr,
			TokenName:    "default",
			KeyringType:  "keyring",
			AuthTokenId:  "at_1234567890",
		}
		assert.NoError(t, r.AddPersona(ctx, p))
		p, err := r.LookupPersona(ctx, p.BoundaryAddr, p.KeyringType, p.TokenName)
		assert.NoError(t, err)
		assert.NotNil(t, p)
	})
}

func TestRepository_RemoveStalePersonas(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s)
	require.NoError(t, err)

	staleTime := time.Now().Add(-(personaStalenessLimit + 1*time.Hour))
	oldNotStaleTime := time.Now().Add(-(personaStalenessLimit - 1*time.Hour))
	addr := "address"
	p := &Persona{
		BoundaryAddr: "address",
		TokenName:    "default",
		KeyringType:  "keyring",
		AuthTokenId:  "at_1234567890",
	}
	for i := 0; i < personaLimit; i++ {
		p = p.clone()
		p.BoundaryAddr = fmt.Sprintf("%s%d", addr, i)
		assert.NoError(t, r.AddPersona(ctx, p))
		switch i % 3 {
		case 0:
			p.LastAccessedTime = staleTime
			_, err := r.rw.Update(ctx, p, []string{"LastAccessedTime"}, nil)
			require.NoError(t, err)
		case 1:
			p.LastAccessedTime = oldNotStaleTime
			_, err := r.rw.Update(ctx, p, []string{"LastAccessedTime"}, nil)
			require.NoError(t, err)
		}
	}

	assert.NoError(t, r.RemoveStalePersonas(ctx))
	lp, err := r.ListPersonas(ctx)
	assert.NoError(t, err)
	assert.Len(t, lp, personaLimit*2/3)
}

func TestRepository_RefreshTargets(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s)
	require.NoError(t, err)

	addr := "address"
	p := &Persona{
		BoundaryAddr: addr,
		TokenName:    "default",
		KeyringType:  "keyring",
		AuthTokenId:  "at_1234567890",
	}
	require.NoError(t, r.AddPersona(ctx, p))

	ts := []*targets.Target{
		{
			Id:                "ttcp_1",
			Name:              "name1",
			Address:           "address1",
			Type:              "tcp",
			SessionMaxSeconds: 111,
		},
		{
			Id:                "ttcp_2",
			Name:              "name2",
			Address:           "address2",
			Type:              "tcp",
			SessionMaxSeconds: 222,
		},
		{
			Id:                "ttcp_3",
			Name:              "name3",
			Address:           "address3",
			Type:              "tcp",
			SessionMaxSeconds: 333,
		},
	}
	cases := []struct {
		name          string
		persona       *Persona
		targets       []*targets.Target
		wantCount     int
		errorContains string
	}{
		{
			name:      "Success",
			persona:   p,
			targets:   ts,
			wantCount: len(ts),
		},
		{
			name:    "repeated target with different values",
			persona: p,
			targets: append(ts, &targets.Target{
				Id:   ts[0].Id,
				Name: "a different name",
			}),
			wantCount: len(ts),
		},
		{
			name:          "nil persona",
			persona:       nil,
			targets:       ts,
			errorContains: "persona is nil",
		},
		{
			name: "missing token name",
			persona: &Persona{
				BoundaryAddr: p.BoundaryAddr,
				KeyringType:  p.KeyringType,
			},
			targets:       ts,
			errorContains: "token name is missing",
		},
		{
			name: "missing boundary address",
			persona: &Persona{
				TokenName:   p.TokenName,
				KeyringType: p.KeyringType,
			},
			targets:       ts,
			errorContains: "boundary address is missing",
		},
		{
			name: "missing keyring type",
			persona: &Persona{
				BoundaryAddr: p.BoundaryAddr,
				TokenName:    p.TokenName,
			},
			targets:       ts,
			errorContains: "keyring type is missing",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.RefreshTargets(ctx, tc.persona, tc.targets)
			if tc.errorContains == "" {
				assert.NoError(t, err)
				rw := db.New(s.conn)
				var got []*Target
				require.NoError(t, rw.SearchWhere(ctx, &got, "true", nil))
				assert.Len(t, got, tc.wantCount)
			} else {
				assert.ErrorContains(t, err, tc.errorContains)
			}
		})
	}
}

func TestRepository_SaveError(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, WithDebug(true))
	require.NoError(t, err)

	r, err := NewRepository(ctx, s)
	require.NoError(t, err)

	testResource := "test_resource_type"
	testErr := fmt.Errorf("test error for %q", testResource)

	t.Run("empty resource type", func(t *testing.T) {
		assert.ErrorContains(t, r.SaveError(ctx, "", testErr), "resource type is empty")
	})
	t.Run("nil error", func(t *testing.T) {
		assert.ErrorContains(t, r.SaveError(ctx, testResource, nil), "error is nil")
	})
	t.Run("success", func(t *testing.T) {
		assert.NoError(t, r.SaveError(ctx, testResource, testErr))
	})

	assert.NoError(t, r.SaveError(ctx, testResource, testErr))
}
