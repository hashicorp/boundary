// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package pagination_test

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestParseRefreshToken(t *testing.T) {
	testToken := &pbs.ListRefreshToken{
		CreatedTime:         timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
		ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
		PermissionsHash:     []byte("some hash"),
		LastItemId:          "s_1234567890",
		LastItemUpdatedTime: timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
	}
	tokBytes, err := proto.Marshal(testToken)
	require.NoError(t, err)
	tokString := base58.Encode(tokBytes)

	tests := []struct {
		name    string
		token   string
		want    *pbs.ListRefreshToken
		wantErr bool
	}{
		{
			name:  "valid",
			token: tokString,
			want:  testToken,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
		},
		{
			name:    "invalid base58",
			token:   "not a token",
			wantErr: true,
		},
		{
			name:    "invalid proto",
			token:   base58.Encode([]byte("not a token")),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pagination.ParseRefreshToken(context.Background(), tt.token)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tt.want, protocmp.Transform()))
		})
	}
}

func TestMarshalRefreshToken(t *testing.T) {
	testToken := &pbs.ListRefreshToken{
		CreatedTime:         timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
		ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
		PermissionsHash:     []byte("some hash"),
		LastItemId:          "s_1234567890",
		LastItemUpdatedTime: timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
	}
	tokBytes, err := proto.Marshal(testToken)
	require.NoError(t, err)
	tokString := base58.Encode(tokBytes)

	tests := []struct {
		name    string
		token   *pbs.ListRefreshToken
		want    string
		wantErr bool
	}{
		{
			name:  "valid",
			token: testToken,
			want:  tokString,
		},
		{
			name:    "nil token",
			token:   nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pagination.MarshalRefreshToken(context.Background(), tt.token)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tt.want, protocmp.Transform()))
		})
	}
}

func TestValidateRefreshToken(t *testing.T) {
	fiveDaysAgo := timestamppb.New(time.Now().AddDate(0, 0, -5))
	tests := []struct {
		name          string
		token         *pbs.ListRefreshToken
		grantsHash    []byte
		resourceType  pbs.ResourceType
		wantErrString string
		wantErrCode   errors.Code
	}{
		{
			name: "valid token",
			token: &pbs.ListRefreshToken{
				CreatedTime:         fiveDaysAgo,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:   []byte("some hash"),
			resourceType: pbs.ResourceType_RESOURCE_TYPE_SESSION,
		},
		{
			name:          "nil token",
			token:         nil,
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token was nil",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "no permissions hash",
			token: &pbs.ListRefreshToken{
				CreatedTime:         fiveDaysAgo,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     nil,
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token was missing its permission hash",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "changed permissions hash",
			token: &pbs.ListRefreshToken{
				CreatedTime:         fiveDaysAgo,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some other hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "permissions have changed since refresh token was issued",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "invalid create time",
			token: &pbs.ListRefreshToken{
				CreatedTime:         nil,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token missing create time",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "created in the future",
			token: &pbs.ListRefreshToken{
				CreatedTime:         timestamppb.New(time.Now().AddDate(1, 0, 0)),
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token was created in the future",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "expired",
			token: &pbs.ListRefreshToken{
				CreatedTime:         timestamppb.New(time.Now().AddDate(0, 0, -31)),
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token was expired",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "resource type mismatch",
			token: &pbs.ListRefreshToken{
				CreatedTime:         fiveDaysAgo,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION_RECORDING,
			wantErrString: "refresh token was not created for this resource type",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "last item ID unset",
			token: &pbs.ListRefreshToken{
				CreatedTime:         fiveDaysAgo,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token missing last item ID",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "last item ID unset",
			token: &pbs.ListRefreshToken{
				CreatedTime:         fiveDaysAgo,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token missing last item ID",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "invalid update time",
			token: &pbs.ListRefreshToken{
				CreatedTime:         fiveDaysAgo,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: nil,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token missing last item updated time",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "updated in the future",
			token: &pbs.ListRefreshToken{
				CreatedTime:         fiveDaysAgo,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: timestamppb.New(time.Now().AddDate(1, 0, 0)),
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token last item was updated in the future",
			wantErrCode:   errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pagination.ValidateRefreshToken(context.Background(), tt.token, tt.grantsHash, tt.resourceType)
			if tt.wantErrString != "" {
				require.ErrorContains(t, err, tt.wantErrString)
				require.Equal(t, errors.Convert(err).Code, tt.wantErrCode)
				return
			}
			require.NoError(t, err)
		})
	}
}

type (
	testType struct {
		I int
	}
	testPbType struct {
		I int
	}
	testTypeIface interface {
		testType() *testType
	}
)

func (t *testType) testType() *testType {
	return t
}

func TestFillPage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("fill-on-init-with-remaining", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType) ([]*testType, error) {
			if prevPageLast != nil {
				t.Fatal("Should not have called listItemsFn with non-empty parameter")
			}
			return []*testType{{1}, {2}, {3}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			return &testPbType{item.I}, nil
		}
		items, complete, err := pagination.FillPage(ctx, limit, pageSize, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}, {2}}))
		assert.False(t, complete)
	})
	t.Run("completely-fill-on-init", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType) ([]*testType, error) {
			if prevPageLast != nil {
				t.Fatal("Should not have called listItemsFn with non-empty parameter")
			}
			return []*testType{{1}, {2}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			return &testPbType{item.I}, nil
		}
		items, complete, err := pagination.FillPage(ctx, limit, pageSize, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}, {2}}))
		assert.True(t, complete)
	})
	t.Run("fill-on-subsequent-with-remaining", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType) ([]*testType, error) {
			if prevPageLast != nil {
				assert.Equal(t, 2, prevPageLast.I)
				return []*testType{{3}, {4}, {5}}, nil
			}
			return []*testType{{1}, {2}, {3}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			if item.I%2 == 0 {
				// Filter every other item
				return nil, nil
			}
			return &testPbType{item.I}, nil
		}
		items, complete, err := pagination.FillPage(ctx, limit, pageSize, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}, {3}}))
		assert.False(t, complete)
	})
	t.Run("fill-on-last-page-with-remaining", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType) ([]*testType, error) {
			if prevPageLast != nil {
				assert.Equal(t, 2, prevPageLast.I)
				return []*testType{{3}, {4}}, nil
			}
			return []*testType{{1}, {2}, {3}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			if item.I%2 == 0 {
				// Filter every other item
				return nil, nil
			}
			return &testPbType{item.I}, nil
		}
		items, complete, err := pagination.FillPage(ctx, limit, pageSize, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}, {3}}))
		assert.False(t, complete)
	})
	t.Run("completely-fill-on-subsequent", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType) ([]*testType, error) {
			if prevPageLast != nil {
				assert.Equal(t, 2, prevPageLast.I)
				return []*testType{{3}}, nil
			}
			return []*testType{{1}, {2}, {3}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			if item.I%2 == 0 {
				// Filter every other item
				return nil, nil
			}
			return &testPbType{item.I}, nil
		}
		items, complete, err := pagination.FillPage(ctx, limit, pageSize, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}, {3}}))
		assert.True(t, complete)
	})
	t.Run("dont-fill", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType) ([]*testType, error) {
			if prevPageLast != nil {
				assert.Equal(t, 2, prevPageLast.I)
				return []*testType{{3}}, nil
			}
			return []*testType{{1}, {2}, {3}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			if item.I != 1 {
				// Filter every item except the first
				return nil, nil
			}
			return &testPbType{item.I}, nil
		}
		items, complete, err := pagination.FillPage(ctx, limit, pageSize, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}}))
		assert.True(t, complete)
	})
	t.Run("dont-fill-with-full-last-page", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType) ([]*testType, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{{1}, {2}, {3}}, nil
			case prevPageLast.I == 2:
				return []*testType{{3}, {4}, {5}}, nil
			case prevPageLast.I == 4:
				return nil, nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil
			}
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			if item.I != 1 {
				// Filter every item except the first
				return nil, nil
			}
			return &testPbType{item.I}, nil
		}
		items, complete, err := pagination.FillPage(ctx, limit, pageSize, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}}))
		assert.True(t, complete)
	})
	t.Run("filter-everything", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType) ([]*testType, error) {
			if prevPageLast != nil {
				assert.Equal(t, 2, prevPageLast.I)
				return []*testType{{3}}, nil
			}
			return []*testType{{1}, {2}, {3}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			// Filter every item
			return nil, nil
		}
		items, complete, err := pagination.FillPage(ctx, limit, pageSize, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Len(t, items, 0)
		assert.True(t, complete)
	})
	t.Run("use-with-interface", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast testTypeIface) ([]testTypeIface, error) {
			if prevPageLast != nil {
				t.Fatal("Should not have called listItemsFn with non-empty parameter")
			}
			return []testTypeIface{&testType{1}, &testType{2}, &testType{3}}, nil
		}
		convertAndFilterFn := func(item testTypeIface) (*testPbType, error) {
			return &testPbType{item.testType().I}, nil
		}
		items, complete, err := pagination.FillPage(ctx, limit, pageSize, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}, {2}}))
		assert.False(t, complete)
	})
	t.Run("errors-when-list-errors-immediately", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType) ([]*testType, error) {
			return nil, stderrors.New("failed to list")
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			t.Fatal("Unexpected call to convert function")
			return nil, nil
		}
		items, complete, err := pagination.FillPage(ctx, limit, pageSize, listItemsFn, convertAndFilterFn)
		require.ErrorContains(t, err, "failed to list")
		assert.Empty(t, items)
		assert.False(t, complete)
	})
	t.Run("errors-when-list-errors-subsequently", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType) ([]*testType, error) {
			if prevPageLast != nil {
				return nil, stderrors.New("failed to list subsequently")
			}
			return []*testType{{1}, {2}, {3}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			if item.I != 1 {
				// Filter every item except the first
				return nil, nil
			}
			return &testPbType{item.I}, nil
		}
		items, complete, err := pagination.FillPage(ctx, limit, pageSize, listItemsFn, convertAndFilterFn)
		require.ErrorContains(t, err, "failed to list subsequently")
		assert.Empty(t, items)
		assert.False(t, complete)
	})
	t.Run("errors-when-convert-errors", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType) ([]*testType, error) {
			return []*testType{{1}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			return nil, stderrors.New("failed to convert")
		}
		items, complete, err := pagination.FillPage(ctx, limit, pageSize, listItemsFn, convertAndFilterFn)
		require.ErrorContains(t, err, "failed to convert")
		assert.Empty(t, items)
		assert.False(t, complete)
	})
}
