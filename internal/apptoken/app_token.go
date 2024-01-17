// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const appTokenTableName = "app_token"

// AppToken defines an app token for storage.  It is the root aggregate for
// other entities: AppTokenGrant, AppTokenPeriodicExpiration
type AppToken struct {
	*store.AppToken
	tableName string
}

// NewAppToken creates an in-memory app token with options.  Supported options:
// WithName, WithDescription
func NewAppToken(ctx context.Context, scopeId string, expirationTime time.Time, createdByUserId string, opt ...Option) (*AppToken, error) {
	const op = "apptoken.NewAppToken"
	switch {
	case createdByUserId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing created by user (history id)")
	case scopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	case expirationTime.IsZero():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing expiration time")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &AppToken{
		AppToken: &store.AppToken{
			ScopeId:                        scopeId,
			ExpirationTime:                 &timestamp.Timestamp{Timestamp: timestamppb.New(expirationTime.Truncate(time.Second))},
			CreatedBy:                      createdByUserId,
			Name:                           opts.withName,
			Description:                    opts.withDescription,
			ExpirationIntervalInMaxSeconds: opts.withExpirationInterval,
		},
	}, nil
}

// clone an AppToken.
func (at *AppToken) clone() *AppToken {
	cp := proto.Clone(at.AppToken)
	return &AppToken{
		AppToken: cp.(*store.AppToken),
	}
}

// AllocAppToken makes an empty one in memory
func AllocAppToken() *AppToken {
	return &AppToken{
		AppToken: &store.AppToken{},
	}
}

// TableName returns the table name.
func (at *AppToken) TableName() string {
	if at.tableName != "" {
		return at.tableName
	}
	return appTokenTableName
}

// SetTableName sets the table name.
func (at *AppToken) SetTableName(n string) {
	at.tableName = n
}

// oplog will create oplog metadata for the AppToken.
func (at *AppToken) oplog(ctx context.Context, opType oplog.OpType) (oplog.Metadata, error) {
	const op = "ldap.(Account).oplog"
	switch {
	case at == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing app token")
	case opType == oplog.OpType_OP_TYPE_UNSPECIFIED:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing op type")
	case at.PublicId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	case at.ScopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	metadata := oplog.Metadata{
		"resource-public-id": []string{at.PublicId},
		"resource-type":      []string{"app token"},
		"op-type":            []string{opType.String()},
		"scope-id":           []string{at.ScopeId},
	}
	return metadata, nil
}
