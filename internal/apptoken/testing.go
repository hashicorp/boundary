// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/stretchr/testify/require"
)

func TestWithOptError(ctx context.Context) Option {
	return func(o *options) error {
		return errors.New(ctx, errors.Unknown, "withOptErrors", "with opt error")
	}
}

func TestAppToken(t *testing.T, conn *db.DB, scopeId, createdBy string, grantsStr ...string) *AppToken {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	require.Greaterf(len(grantsStr), 0, "missing grants")
	w := db.New(conn)
	appToken, err := NewAppToken(ctx, scopeId, time.Now().Add(10*time.Minute), createdBy)
	require.NoError(err)

	const fakeScopeId = "o_abcd1234"
	grants := make([]*perms.Grant, 0, len(grantsStr))
	for _, g := range grantsStr {
		grant, err := perms.Parse(ctx, fakeScopeId, g)
		require.NoError(err)
		grants = append(grants, &grant)
	}

	appToken.PublicId, err = newAppTokenId(ctx)
	require.NoError(err)

	appTokenGrants := make([]*AppTokenGrant, 0, len(grantsStr))
	for _, g := range grants {
		ag, err := NewAppTokenGrant(ctx, appToken.PublicId, g.CanonicalString())
		require.NoError(err)
		appTokenGrants = append(appTokenGrants, ag)
	}

	_, err = w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		err := w.Create(ctx, appToken)
		require.NoError(err)

		for _, atg := range appTokenGrants {
			err := w.Create(ctx, atg)
			require.NoError(err)
		}

		return nil
	})
	require.NoError(err)
	gs := make([]*store.AppTokenGrant, 0, len(appTokenGrants))
	for _, g := range appTokenGrants {
		g.CreateTime = appToken.CreateTime
		gs = append(gs, g.AppTokenGrant)
	}
	appToken.Grants = gs
	return appToken
}
