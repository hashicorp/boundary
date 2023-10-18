// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package refreshtoken

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshToken_ToPartialResource(t *testing.T) {
	ctime := time.Now().AddDate(0, 0, -1)
	utime := ctime.Add(time.Hour)
	rt, err := New(context.Background(), ctime, utime, resource.Session, []byte("some-hash"), "some-id", utime)
	require.NoError(t, err)
	res := rt.ToPartialResource()
	assert.Equal(t, res.GetPublicId(), "some-id")
	assert.Equal(t, res.GetResourceType(), resource.Session)
	assert.Equal(t, res.GetUpdateTime(), timestamp.New(utime))
}
