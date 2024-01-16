// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"

	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

const appTokenPeriodicExpirationTableName = "app_token_periodic_expiration_interval"

// AppTokenPeriodicExpiration defines an app token periodic expiration interval
// for storage.
type AppTokenPeriodicExpirationInterval struct {
	*store.AppTokenPeriodicExpirationInterval
	tableName string
}

// NewAppTokenPeriodicExpirationInterval creates an in-memory app token periodic
// expiration interval. No options are currently supported.
func NewAppTokenPeriodicExpirationInterval(ctx context.Context, appTokenId string, maxSeconds uint32, _ ...Option) (*AppTokenPeriodicExpirationInterval, error) {
	const op = "apptoken.NewAppTokenPeriodicExpirationInterval"
	switch {
	case appTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing app token id")
	case maxSeconds == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing max seconds")
	}
	return &AppTokenPeriodicExpirationInterval{
		AppTokenPeriodicExpirationInterval: &store.AppTokenPeriodicExpirationInterval{
			AppTokenId:                     appTokenId,
			ExpirationIntervalInMaxSeconds: maxSeconds,
		},
	}, nil
}

// clone an AppTokenPeriodicExpirationInterval
func (p *AppTokenPeriodicExpirationInterval) clone() *AppTokenPeriodicExpirationInterval {
	cp := proto.Clone(p.AppTokenPeriodicExpirationInterval)
	return &AppTokenPeriodicExpirationInterval{
		AppTokenPeriodicExpirationInterval: cp.(*store.AppTokenPeriodicExpirationInterval),
	}
}

func AllocAppTokenPeriodicExpirationInterval() *AppTokenPeriodicExpirationInterval {
	return &AppTokenPeriodicExpirationInterval{
		AppTokenPeriodicExpirationInterval: &store.AppTokenPeriodicExpirationInterval{},
	}
}

// TableName returns the table name.
func (p *AppTokenPeriodicExpirationInterval) TableName() string {
	if p.tableName != "" {
		return p.tableName
	}
	return appTokenPeriodicExpirationTableName
}

// SetTableName sets the table name.
func (p *AppTokenPeriodicExpirationInterval) SetTableName(n string) {
	p.tableName = n
}
