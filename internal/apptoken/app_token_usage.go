package apptoken

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const appTokenUsageTableName = "app_token_usage"

// AppTokenUsage defines an app token usage entity for storage.
type AppTokenUsage struct {
	*store.AppTokenUsage
	tableName string
}

// NewAppToken creates an in-memory app token with options.  Supported options:
// WithName, WithDescription
func NewAppTokenUsage(ctx context.Context, appTokenId, clientTcpAddress, requestMethod, requestPath string, createdTime time.Time, _ ...Option) (*AppTokenUsage, error) {
	const op = "apptoken.NewAppToken"
	switch {
	case appTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing app token id")
	case clientTcpAddress == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing cleint tcp address")
	case requestMethod == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing request method")
	case requestPath == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing request path")
	case createdTime.IsZero():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing created time")
	}

	return &AppTokenUsage{
		AppTokenUsage: &store.AppTokenUsage{
			AppTokenId:       appTokenId,
			ClientTcpAddress: clientTcpAddress,
			CreateTime:       &timestamp.Timestamp{Timestamp: timestamppb.New(createdTime)},
			RequestMethod:    requestMethod,
			RequestPath:      requestPath,
		},
	}, nil
}

// clone an AppToken.
func (atu *AppTokenUsage) clone() *AppTokenUsage {
	cp := proto.Clone(atu.AppTokenUsage)
	return &AppTokenUsage{
		AppTokenUsage: cp.(*store.AppTokenUsage),
	}
}

// AllocAppTokenUsage makes an empty AppTokenUsage in memory
func AllocAppTokenUsage() *AppTokenUsage {
	return &AppTokenUsage{
		AppTokenUsage: &store.AppTokenUsage{},
	}
}

// TableName returns the table name.
func (atu *AppTokenUsage) TableName() string {
	if atu.tableName != "" {
		return atu.tableName
	}
	return appTokenUsageTableName
}

// SetTableName sets the table name.
func (atu *AppTokenUsage) SetTableName(n string) {
	atu.tableName = n
}
