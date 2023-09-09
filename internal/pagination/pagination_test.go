// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package pagination

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test_parseRefreshToken(t *testing.T) {
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
			got, err := parseRefreshToken(context.Background(), tt.token)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tt.want, protocmp.Transform()))
		})
	}
}

func Test_marshalRefreshToken(t *testing.T) {
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
			got, err := marshalRefreshToken(context.Background(), tt.token)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tt.want, protocmp.Transform()))
		})
	}
}

func Test_validateRefreshToken(t *testing.T) {
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
			err := validateRefreshToken(context.Background(), tt.token, tt.grantsHash, tt.resourceType)
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
	testRequest struct {
		PageSize     uint32
		RefreshToken string
	}
	testType struct {
		I int
	}
	testPbType struct {
		I int
	}
	testTypeIface interface {
		testType() *testType
	}
	testGrantHasher struct {
		HashFn func() ([]byte, error)
	}
	testRepo struct {
		DeletedIdsFn          func(time.Time) ([]string, error)
		EstimatedTotalItemsFn func() (int, error)
	}
)

func (t *testRequest) GetPageSize() uint32 {
	return t.PageSize
}

func (t *testRequest) GetRefreshToken() string {
	return t.RefreshToken
}

func (t *testType) testType() *testType {
	return t
}

func (t *testPbType) GetId() string {
	return "some-id"
}

func (t *testPbType) GetUpdatedTime() *timestamppb.Timestamp {
	return timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC))
}

func (t *testGrantHasher) GrantsHash(context.Context) ([]byte, error) {
	return t.HashFn()
}

func (t *testRepo) ListDeletedIds(_ context.Context, tm time.Time) ([]string, error) {
	return t.DeletedIdsFn(tm)
}

func (t *testRepo) GetTotalItems(context.Context) (int, error) {
	return t.EstimatedTotalItemsFn()
}

func TestPaginateRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("empty-max-page-size", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(0)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		req := &testRequest{}
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			return nil, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			return nil, nil
		}
		grantsHasher := &testGrantHasher{}
		repo := &testRepo{}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.ErrorContains(t, err, "max page size is required")
		assert.Empty(t, listResp)
	})
	t.Run("empty-resource-type", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_UNSPECIFIED
		req := &testRequest{}
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			return nil, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			return nil, nil
		}
		grantsHasher := &testGrantHasher{}
		repo := &testRepo{}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.ErrorContains(t, err, "resource type is required")
		assert.Empty(t, listResp)
	})
	t.Run("empty-request", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		req := (*testRequest)(nil)
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			return nil, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			return nil, nil
		}
		grantsHasher := &testGrantHasher{}
		repo := &testRepo{}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.ErrorContains(t, err, "the request is required")
		assert.Empty(t, listResp)
	})
	t.Run("empty-item-lister", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		req := &testRequest{}
		listItemsFn := (func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error))(nil)
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			return nil, nil
		}
		grantsHasher := &testGrantHasher{}
		repo := &testRepo{}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.ErrorContains(t, err, "item list function is required")
		assert.Empty(t, listResp)
	})
	t.Run("empty-convert-filterer", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		req := &testRequest{}
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			return nil, nil
		}
		convertAndFilterFn := (func(item *testType) (*testPbType, error))(nil)
		grantsHasher := &testGrantHasher{}
		repo := &testRepo{}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.ErrorContains(t, err, "convert-and-filter function is required")
		assert.Empty(t, listResp)
	})
	t.Run("empty-grants-hasher", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		req := &testRequest{}
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			return nil, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			return nil, nil
		}
		grantsHasher := (*testGrantHasher)(nil)
		repo := &testRepo{}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.ErrorContains(t, err, "grants hasher is required")
		assert.Empty(t, listResp)
	})
	t.Run("empty-repo", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		req := &testRequest{}
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			return nil, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			return nil, nil
		}
		grantsHasher := &testGrantHasher{}
		repo := (*testRepo)(nil)
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.ErrorContains(t, err, "repository is required")
		assert.Empty(t, listResp)
	})

	t.Run("fails-when-grants-hasher-fails", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		req := &testRequest{
			PageSize:     2,
			RefreshToken: "",
		}
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			assert.Empty(t, prevPageLast)
			assert.Empty(t, refreshToken)
			return nil, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			t.Fatal("Should not have called convertAndFilterFn")
			return nil, nil
		}
		grantsHasher := &testGrantHasher{
			HashFn: func() ([]byte, error) {
				return nil, stderrors.New("some error")
			},
		}
		repo := &testRepo{
			DeletedIdsFn: func(time.Time) ([]string, error) {
				t.Fatal("Should not have requested the deleted Ids")
				return nil, nil
			},
			EstimatedTotalItemsFn: func() (int, error) {
				return 100, nil
			},
		}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.ErrorContains(t, err, "some error")
		assert.Empty(t, listResp)
	})
	t.Run("fails-with-a-junk-refresh-token", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		req := &testRequest{
			PageSize:     2,
			RefreshToken: "not-a-token",
		}
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			assert.Empty(t, prevPageLast)
			assert.Empty(t, refreshToken)
			return nil, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			t.Fatal("Should not have called convertAndFilterFn")
			return nil, nil
		}
		grantsHasher := &testGrantHasher{
			HashFn: func() ([]byte, error) {
				return []byte("some hash"), nil
			},
		}
		repo := &testRepo{
			DeletedIdsFn: func(time.Time) ([]string, error) {
				t.Fatal("Should not have requested the deleted Ids")
				return nil, nil
			},
			EstimatedTotalItemsFn: func() (int, error) {
				return 100, nil
			},
		}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.ErrorContains(t, err, "invalid base58")
		assert.Empty(t, listResp)
	})
	t.Run("fails-with-invalid-request-token", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		refreshToken := &pbs.ListRefreshToken{
			PermissionsHash: []byte("some other hash"),
		}
		marshaledToken, err := marshalRefreshToken(ctx, refreshToken)
		require.NoError(t, err)
		req := &testRequest{
			PageSize:     2,
			RefreshToken: marshaledToken,
		}
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			assert.Empty(t, prevPageLast)
			assert.Empty(t, refreshToken)
			return nil, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			t.Fatal("Should not have called convertAndFilterFn")
			return nil, nil
		}
		grantsHasher := &testGrantHasher{
			HashFn: func() ([]byte, error) {
				return []byte("some hash"), nil
			},
		}
		repo := &testRepo{
			DeletedIdsFn: func(time.Time) ([]string, error) {
				t.Fatal("Should not have requested the deleted Ids")
				return nil, nil
			},
			EstimatedTotalItemsFn: func() (int, error) {
				return 100, nil
			},
		}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.ErrorContains(t, err, "permissions have changed since refresh token was issued")
		assert.Empty(t, listResp)
	})
	t.Run("fails-when-listing-deleted-ids-errors", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		refreshToken := &pbs.ListRefreshToken{
			CreatedTime:         timestamppb.New(time.Now().Add(-time.Hour)),
			ResourceType:        resourceType,
			LastItemId:          "some-id",
			LastItemUpdatedTime: timestamppb.New(time.Now().Add(-2 * time.Hour)),
			PermissionsHash:     []byte("some hash"),
		}
		marshaledToken, err := marshalRefreshToken(ctx, refreshToken)
		require.NoError(t, err)
		req := &testRequest{
			PageSize:     2,
			RefreshToken: marshaledToken,
		}
		listItemsFn := func(prevPageLast *testType, rt *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			assert.Empty(t, prevPageLast)
			assert.Empty(t, cmp.Diff(refreshToken, rt, protocmp.Transform()))
			assert.Equal(t, 3, limit)
			return nil, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			t.Fatal("Should not have called convertAndFilterFn")
			return nil, nil
		}
		grantsHasher := &testGrantHasher{
			HashFn: func() ([]byte, error) {
				return []byte("some hash"), nil
			},
		}
		repo := &testRepo{
			DeletedIdsFn: func(time.Time) ([]string, error) {
				return nil, stderrors.New("some error")
			},
			EstimatedTotalItemsFn: func() (int, error) {
				return 100, nil
			},
		}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.ErrorContains(t, err, "some error")
		assert.Empty(t, listResp)
	})
	t.Run("fails-when-estimate-count-fails", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		req := &testRequest{
			PageSize:     2,
			RefreshToken: "",
		}
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			assert.Empty(t, prevPageLast)
			assert.Empty(t, refreshToken)
			assert.Equal(t, 3, limit)
			return nil, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			t.Fatal("Should not have called convertAndFilterFn")
			return nil, nil
		}
		grantsHasher := &testGrantHasher{
			HashFn: func() ([]byte, error) {
				return []byte("some hash"), nil
			},
		}
		repo := &testRepo{
			DeletedIdsFn: func(time.Time) ([]string, error) {
				t.Fatal("Should not have requested the deleted Ids")
				return nil, nil
			},
			EstimatedTotalItemsFn: func() (int, error) {
				return 0, stderrors.New("some error")
			},
		}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.ErrorContains(t, err, "some error")
		assert.Empty(t, listResp)
	})

	t.Run("uses-max-page-size-when-page-size-not-specified", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		req := &testRequest{
			PageSize:     0,
			RefreshToken: "",
		}
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			assert.Empty(t, prevPageLast)
			assert.Empty(t, refreshToken)
			assert.Equal(t, 1001, limit)
			return nil, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			t.Fatal("Should not have called convertAndFilterFn")
			return nil, nil
		}
		grantsHasher := &testGrantHasher{
			HashFn: func() ([]byte, error) {
				return []byte("some hash"), nil
			},
		}
		repo := &testRepo{
			DeletedIdsFn: func(time.Time) ([]string, error) {
				t.Fatal("Should not have requested the deleted Ids")
				return nil, nil
			},
			EstimatedTotalItemsFn: func() (int, error) {
				return 100, nil
			},
		}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.NoError(t, err)
		assert.Empty(t, listResp.Items)
		assert.True(t, listResp.CompleteListing)
		assert.Empty(t, listResp.DeletedIds) // No input refresh token, so should include no ids
		assert.Equal(t, 100, listResp.EstimatedItemCount)
		assert.Empty(t, listResp.MarshaledRefreshToken)
	})
	t.Run("no-rows-no-request-token", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		req := &testRequest{
			PageSize:     2,
			RefreshToken: "",
		}
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			assert.Empty(t, prevPageLast)
			assert.Empty(t, refreshToken)
			assert.Equal(t, 3, limit)
			return nil, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			t.Fatal("Should not have called convertAndFilterFn")
			return nil, nil
		}
		grantsHasher := &testGrantHasher{
			HashFn: func() ([]byte, error) {
				return []byte("some hash"), nil
			},
		}
		repo := &testRepo{
			DeletedIdsFn: func(time.Time) ([]string, error) {
				t.Fatal("Should not have requested the deleted Ids")
				return nil, nil
			},
			EstimatedTotalItemsFn: func() (int, error) {
				return 100, nil
			},
		}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.NoError(t, err)
		assert.Empty(t, listResp.Items)
		assert.True(t, listResp.CompleteListing)
		assert.Empty(t, listResp.DeletedIds) // No input refresh token, so should include no ids
		assert.Equal(t, 100, listResp.EstimatedItemCount)
		assert.Empty(t, listResp.MarshaledRefreshToken)
	})
	t.Run("some-rows-no-request-token", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		req := &testRequest{
			PageSize:     2,
			RefreshToken: "",
		}
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			assert.Empty(t, prevPageLast)
			assert.Empty(t, refreshToken)
			assert.Equal(t, 3, limit)
			return []*testType{{1}, {2}, {3}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			return &testPbType{item.I}, nil
		}
		grantsHasher := &testGrantHasher{
			HashFn: func() ([]byte, error) {
				return []byte("some hash"), nil
			},
		}
		repo := &testRepo{
			DeletedIdsFn: func(time.Time) ([]string, error) {
				t.Fatal("Should not have requested the deleted Ids")
				return nil, nil
			},
			EstimatedTotalItemsFn: func() (int, error) {
				return 100, nil
			},
		}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(listResp.Items, []*testPbType{{1}, {2}}))
		assert.False(t, listResp.CompleteListing)
		assert.Empty(t, listResp.DeletedIds) // No input refresh token, so should include no ids
		assert.Equal(t, 100, listResp.EstimatedItemCount)
		assert.NotEmpty(t, listResp.MarshaledRefreshToken)
		refreshToken, err := parseRefreshToken(ctx, listResp.MarshaledRefreshToken)
		require.NoError(t, err)
		// Created time should be ~within 10 seconds of now
		now := time.Now()
		assert.True(t, refreshToken.CreatedTime.AsTime().Add(-10*time.Second).Before(now))
		assert.True(t, refreshToken.CreatedTime.AsTime().Add(10*time.Second).After(now))
		assert.Equal(t, "some-id", refreshToken.LastItemId)
		assert.True(t, refreshToken.LastItemUpdatedTime.AsTime().Equal((&testPbType{}).GetUpdatedTime().AsTime()))
		assert.Equal(t, []byte("some hash"), refreshToken.PermissionsHash)
		assert.Equal(t, resourceType, refreshToken.ResourceType)
	})
	t.Run("some-rows-and-request-token", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		refreshToken := &pbs.ListRefreshToken{
			CreatedTime:         timestamppb.New(time.Now().Add(-time.Hour)),
			ResourceType:        resourceType,
			LastItemId:          "some-id",
			LastItemUpdatedTime: timestamppb.New(time.Now().Add(-2 * time.Hour)),
			PermissionsHash:     []byte("some hash"),
		}
		marshaledToken, err := marshalRefreshToken(ctx, refreshToken)
		require.NoError(t, err)
		req := &testRequest{
			PageSize:     2,
			RefreshToken: marshaledToken,
		}
		listItemsFn := func(prevPageLast *testType, rt *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			assert.Empty(t, cmp.Diff(refreshToken, rt, protocmp.Transform()))
			assert.Equal(t, 3, limit)
			return []*testType{{1}, {2}, {3}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			return &testPbType{item.I}, nil
		}
		grantsHasher := &testGrantHasher{
			HashFn: func() ([]byte, error) {
				return []byte("some hash"), nil
			},
		}
		repo := &testRepo{
			DeletedIdsFn: func(time.Time) ([]string, error) {
				return []string{"id1", "id2"}, nil
			},
			EstimatedTotalItemsFn: func() (int, error) {
				return 100, nil
			},
		}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(listResp.Items, []*testPbType{{1}, {2}}))
		assert.False(t, listResp.CompleteListing)
		assert.Equal(t, []string{"id1", "id2"}, listResp.DeletedIds)
		assert.Equal(t, 100, listResp.EstimatedItemCount)
		assert.NotEmpty(t, listResp.MarshaledRefreshToken)
		refreshToken2, err := parseRefreshToken(ctx, listResp.MarshaledRefreshToken)
		require.NoError(t, err)
		// Created time should be ~within 10 seconds of now
		now := time.Now()
		assert.True(t, refreshToken2.CreatedTime.AsTime().Add(-10*time.Second).Before(now))
		assert.True(t, refreshToken2.CreatedTime.AsTime().Add(10*time.Second).After(now))
		assert.Equal(t, "some-id", refreshToken2.LastItemId)
		assert.True(t, refreshToken2.LastItemUpdatedTime.AsTime().Equal((&testPbType{}).GetUpdatedTime().AsTime()))
		assert.Equal(t, []byte("some hash"), refreshToken2.PermissionsHash)
		assert.Equal(t, resourceType, refreshToken2.ResourceType)
	})
	t.Run("no-rows-and-request-token", func(t *testing.T) {
		t.Parallel()
		maxPageSize := uint(1000)
		resourceType := pbs.ResourceType_RESOURCE_TYPE_SESSION
		refreshToken := &pbs.ListRefreshToken{
			CreatedTime:         timestamppb.New(time.Now().Add(-time.Hour)),
			ResourceType:        resourceType,
			LastItemId:          "some-id",
			LastItemUpdatedTime: timestamppb.New(time.Now().Add(-2 * time.Hour)),
			PermissionsHash:     []byte("some hash"),
		}
		marshaledToken, err := marshalRefreshToken(ctx, refreshToken)
		require.NoError(t, err)
		req := &testRequest{
			PageSize:     2,
			RefreshToken: marshaledToken,
		}
		listItemsFn := func(prevPageLast *testType, rt *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			assert.Empty(t, cmp.Diff(refreshToken, rt, protocmp.Transform()))
			assert.Equal(t, 3, limit)
			return nil, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			t.Fatal("Should not have converted any items")
			return nil, nil
		}
		grantsHasher := &testGrantHasher{
			HashFn: func() ([]byte, error) {
				return []byte("some hash"), nil
			},
		}
		repo := &testRepo{
			DeletedIdsFn: func(time.Time) ([]string, error) {
				return []string{"id1", "id2"}, nil
			},
			EstimatedTotalItemsFn: func() (int, error) {
				return 100, nil
			},
		}
		listResp, err := PaginateRequest(ctx, maxPageSize, resourceType, req, listItemsFn, convertAndFilterFn, grantsHasher, repo)
		require.NoError(t, err)
		assert.Empty(t, listResp.Items)
		assert.True(t, listResp.CompleteListing)
		assert.Equal(t, []string{"id1", "id2"}, listResp.DeletedIds)
		assert.Equal(t, 100, listResp.EstimatedItemCount)
		assert.NotEmpty(t, listResp.MarshaledRefreshToken)
		refreshToken2, err := parseRefreshToken(ctx, listResp.MarshaledRefreshToken)
		require.NoError(t, err)
		// Created time should be ~within 10 seconds of now
		now := time.Now()
		assert.True(t, refreshToken2.CreatedTime.AsTime().Add(-10*time.Second).Before(now))
		assert.True(t, refreshToken2.CreatedTime.AsTime().Add(10*time.Second).After(now))
		assert.Equal(t, refreshToken.LastItemId, refreshToken2.LastItemId)
		assert.True(t, refreshToken2.LastItemUpdatedTime.AsTime().Equal(refreshToken.LastItemUpdatedTime.AsTime()))
		assert.Equal(t, []byte("some hash"), refreshToken2.PermissionsHash)
		assert.Equal(t, resourceType, refreshToken2.ResourceType)
	})
}

func Test_fillPage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	refreshToken := &pbs.ListRefreshToken{
		CreatedTime:         timestamppb.Now(),
		ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
		PermissionsHash:     []byte("some bytes"),
		LastItemId:          "last_id",
		LastItemUpdatedTime: timestamppb.New(time.Now().Add(-time.Hour)),
	}

	t.Run("no-rows", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			if prevPageLast != nil {
				t.Fatal("Should not have called listItemsFn with non-empty parameter")
			}
			return nil, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			t.Fatal("Should not have called convertAndFilterFn")
			return nil, nil
		}
		items, complete, err := fillPage(ctx, limit, pageSize, refreshToken, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, items)
		assert.True(t, complete)
	})
	t.Run("fill-on-init-with-remaining", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			if prevPageLast != nil {
				t.Fatal("Should not have called listItemsFn with non-empty parameter")
			}
			return []*testType{{1}, {2}, {3}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			return &testPbType{item.I}, nil
		}
		items, complete, err := fillPage(ctx, limit, pageSize, refreshToken, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}, {2}}))
		assert.False(t, complete)
	})
	t.Run("completely-fill-on-init", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			if prevPageLast != nil {
				t.Fatal("Should not have called listItemsFn with non-empty parameter")
			}
			return []*testType{{1}, {2}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			return &testPbType{item.I}, nil
		}
		items, complete, err := fillPage(ctx, limit, pageSize, refreshToken, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}, {2}}))
		assert.True(t, complete)
	})
	t.Run("fill-on-subsequent-with-remaining", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
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
		items, complete, err := fillPage(ctx, limit, pageSize, refreshToken, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}, {3}}))
		assert.False(t, complete)
	})
	t.Run("fill-on-last-page-with-remaining", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
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
		items, complete, err := fillPage(ctx, limit, pageSize, refreshToken, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}, {3}}))
		assert.False(t, complete)
	})
	t.Run("completely-fill-on-subsequent", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
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
		items, complete, err := fillPage(ctx, limit, pageSize, refreshToken, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}, {3}}))
		assert.True(t, complete)
	})
	t.Run("dont-fill", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
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
		items, complete, err := fillPage(ctx, limit, pageSize, refreshToken, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}}))
		assert.True(t, complete)
	})
	t.Run("dont-fill-with-full-last-page", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
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
		items, complete, err := fillPage(ctx, limit, pageSize, refreshToken, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}}))
		assert.True(t, complete)
	})
	t.Run("filter-everything", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			if prevPageLast != nil {
				assert.Equal(t, 2, prevPageLast.I)
				return []*testType{{3}}, nil
			}
			return []*testType{{1}, {2}, {3}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			// Filtery item
			return nil, nil
		}
		items, complete, err := fillPage(ctx, limit, pageSize, refreshToken, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Len(t, items, 0)
		assert.True(t, complete)
	})
	t.Run("use-with-interface", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast testTypeIface, refreshToken *pbs.ListRefreshToken, limit int) ([]testTypeIface, error) {
			if prevPageLast != nil {
				t.Fatal("Should not have called listItemsFn with non-empty parameter")
			}
			return []testTypeIface{&testType{1}, &testType{2}, &testType{3}}, nil
		}
		convertAndFilterFn := func(item testTypeIface) (*testPbType, error) {
			return &testPbType{item.testType().I}, nil
		}
		items, complete, err := fillPage(ctx, limit, pageSize, refreshToken, listItemsFn, convertAndFilterFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(items, []*testPbType{{1}, {2}}))
		assert.False(t, complete)
	})
	t.Run("errors-when-list-errors-immediately", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			return nil, stderrors.New("failed to list")
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			t.Fatal("Should not have called convertAndFilterFn")
			return nil, nil
		}
		items, complete, err := fillPage(ctx, limit, pageSize, refreshToken, listItemsFn, convertAndFilterFn)
		require.ErrorContains(t, err, "failed to list")
		assert.Empty(t, items)
		assert.False(t, complete)
	})
	t.Run("errors-when-list-errors-subsequently", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
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
		items, complete, err := fillPage(ctx, limit, pageSize, refreshToken, listItemsFn, convertAndFilterFn)
		require.ErrorContains(t, err, "failed to list subsequently")
		assert.Empty(t, items)
		assert.False(t, complete)
	})
	t.Run("errors-when-convert-errors", func(t *testing.T) {
		t.Parallel()
		limit := 3
		pageSize := 2
		listItemsFn := func(prevPageLast *testType, refreshToken *pbs.ListRefreshToken, limit int) ([]*testType, error) {
			return []*testType{{1}}, nil
		}
		convertAndFilterFn := func(item *testType) (*testPbType, error) {
			return nil, stderrors.New("failed to convert")
		}
		items, complete, err := fillPage(ctx, limit, pageSize, refreshToken, listItemsFn, convertAndFilterFn)
		require.ErrorContains(t, err, "failed to convert")
		assert.Empty(t, items)
		assert.False(t, complete)
	})
}
