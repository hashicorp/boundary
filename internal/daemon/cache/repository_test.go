// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cache

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_AddPersona(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s)
	require.NoError(t, err)

	addr := "address"
	p := &Persona{
		BoundaryAddr: addr,
		TokenName:    "default",
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
	gotP, err := r.LookupPersona(ctx, addr, p.TokenName)
	assert.NoError(t, err)
	assert.Nil(t, gotP)

	p, err = r.LookupPersona(ctx, addr+"0", p.TokenName)
	assert.NoError(t, err)
	assert.NotNil(t, p)
	t.Logf("got %#v", p)
}

func TestRepository_LookupPersona(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s)
	require.NoError(t, err)

	t.Run("empty address", func(t *testing.T) {
		p, err := r.LookupPersona(ctx, "", "token")
		assert.ErrorContains(t, err, "address is empty")
		assert.Nil(t, p)
	})
	t.Run("empty token name", func(t *testing.T) {
		p, err := r.LookupPersona(ctx, "address", "")
		assert.ErrorContains(t, err, "token name is empty")
		assert.Nil(t, p)
	})
	t.Run("not found", func(t *testing.T) {
		p, err := r.LookupPersona(ctx, "address", "token")
		assert.NoError(t, err)
		assert.Nil(t, p)
	})
	t.Run("found", func(t *testing.T) {
		addr := "address"
		p := &Persona{
			BoundaryAddr: addr,
			TokenName:    "default",
			AuthTokenId:  "at_1234567890",
		}
		assert.NoError(t, r.AddPersona(ctx, p))
		p, err := r.LookupPersona(ctx, p.BoundaryAddr, p.TokenName)
		assert.NoError(t, err)
		assert.NotNil(t, p)
	})
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
			},
			targets:       ts,
			errorContains: "token name is missing",
		},
		{
			name: "missing boundary address",
			persona: &Persona{
				TokenName: p.TokenName,
			},
			targets:       ts,
			errorContains: "boundary address is missing",
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
