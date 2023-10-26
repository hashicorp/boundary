// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"

	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/perms"
	"google.golang.org/protobuf/proto"
)

const appTokenGrantTableName = "app_token_grant"

// AppTokenGrant defines an app token grant for storage
type AppTokenGrant struct {
	*store.AppTokenGrant
	tableName string
}

// NewAppTokenGrant creates a new in memory app token grant
func NewAppTokenGrant(ctx context.Context, appTokenId string, grant string) (*AppTokenGrant, error) {
	const op = "apptokengrant.NewAppTokenGrant"
	switch {
	case appTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing app token id")
	case grant == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grant")
	}

	// Validate that the grant parses successfully. Note that we fake the scope
	// here to avoid a lookup as the scope is only relevant at actual ACL
	// checking time and we just care that it parses correctly.
	perm, err := perms.Parse(ctx, "o_abcd1234", grant)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("parsing grant string"))
	}
	return &AppTokenGrant{
		AppTokenGrant: &store.AppTokenGrant{
			AppTokenId:     appTokenId,
			RawGrant:       grant,
			CanonicalGrant: perm.CanonicalString(),
		},
	}, nil
}

// clone an AppTokenGrant.
func (atg *AppTokenGrant) clone() *AppTokenGrant {
	cp := proto.Clone(atg.AppTokenGrant)
	return &AppTokenGrant{
		AppTokenGrant: cp.(*store.AppTokenGrant),
	}
}

// AllocAppTokenGrant makes an empty one in memory
func AllocAppTokenGrant() *AppTokenGrant {
	return &AppTokenGrant{
		AppTokenGrant: &store.AppTokenGrant{},
	}
}

// TableName returns the table name.
func (atg *AppTokenGrant) TableName() string {
	if atg.tableName != "" {
		return atg.tableName
	}
	return appTokenGrantTableName
}

// SetTableName sets the table name.
func (at *AppTokenGrant) SetTableName(n string) {
	at.tableName = n
}
