// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
)

type appTokenAgg struct {
	PublicId        string
	CreateTime      time.Time
	ExpirationTime  time.Time
	Name            string
	Description     string
	CreatedBy       string
	ScopeId         string
	CannonicalGrant string
	RawGrant        string
}

func (agg appTokenAgg) TableName() string {
	return "app_token_agg"
}

// ReadAppToken takes an appTokenId and returns the AppToken with its AppTokenGrants
func (r *Repository) ReadAppToken(ctx context.Context, appTokenId string, opt ...Option) (*AppToken, []*AppTokenGrant, error) {
	const op = "apptoken.(Repository).ReadAppToken"

	switch {
	case appTokenId == "":
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing app token id")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		limit = opts.withLimit
	}

	var appTokenAggs []*appTokenAgg

	err = r.reader.SearchWhere(ctx, &appTokenAggs, "public_id = ?", []any{appTokenId}, db.WithLimit(limit))
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	appTokenGrants := make([]*AppTokenGrant, len(appTokenAggs))

	appToken := AllocAppToken()
	if len(appTokenAggs) > 0 {
		appToken.PublicId = appTokenAggs[0].PublicId
		appToken.CreateTime = timestamp.New(appTokenAggs[0].CreateTime)
		appToken.ExpirationTime = timestamp.New(appTokenAggs[0].ExpirationTime)
		appToken.Name = appTokenAggs[0].Name
		appToken.Description = appTokenAggs[0].Description
		appToken.CreatedBy = appTokenAggs[0].CreatedBy
		appToken.ScopeId = appTokenAggs[0].ScopeId
	}
	for _, agg := range appTokenAggs {
		g := AllocAppTokenGrant()
		g.AppTokenId = appToken.PublicId
		g.CanonicalGrant = agg.CannonicalGrant
		g.RawGrant = agg.RawGrant
		g.CreateTime = timestamp.New(agg.CreateTime)
		appTokenGrants = append(appTokenGrants, g)
	}

	return appToken, appTokenGrants, nil
}
