package pagination_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
)

type fakeItem struct {
	publicId     string
	updateTime   *timestamp.Timestamp
	resourceType resource.Type
}

func (f *fakeItem) GetPublicId() string {
	return f.publicId
}

func (f *fakeItem) GetUpdateTime() *timestamp.Timestamp {
	return f.updateTime
}

func (f *fakeItem) GetResourceType() resource.Type {
	return f.resourceType
}

func TestValidateItem(t *testing.T) {
	t.Parallel()
	t.Run("nil item", func(t *testing.T) {
		err := pagination.ValidateItem(context.Background(), nil)
		require.ErrorContains(t, err, "nil item")
	})
	t.Run("nil typed item", func(t *testing.T) {
		err := pagination.ValidateItem(context.Background(), (*fakeItem)(nil))
		require.ErrorContains(t, err, "nil item")
	})
	t.Run("missing public id", func(t *testing.T) {
		err := pagination.ValidateItem(context.Background(), &fakeItem{"", timestamp.New(time.Now()), resource.Session})
		require.ErrorContains(t, err, "missing public id")
	})
	t.Run("missing update time", func(t *testing.T) {
		err := pagination.ValidateItem(context.Background(), &fakeItem{"some_id", nil, resource.Session})
		require.ErrorContains(t, err, "missing update time")
	})
	t.Run("zero update time", func(t *testing.T) {
		err := pagination.ValidateItem(context.Background(), &fakeItem{"some_id", timestamp.New(time.Time{}), resource.Session})
		require.ErrorContains(t, err, "missing update time")
	})
	t.Run("missing resource type", func(t *testing.T) {
		err := pagination.ValidateItem(context.Background(), &fakeItem{"some_id", timestamp.New(time.Now()), resource.Unknown})
		require.ErrorContains(t, err, "missing resource type")
	})
}
