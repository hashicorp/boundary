// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package job

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/require"
)

func Test_newTableRewrappingJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	extWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, extWrapper)

	_, err := newTableRewrappingJob(context.Background(), nil, "")
	require.Error(t, err)
	_, err = newTableRewrappingJob(context.Background(), kmsCache, "")
	require.Error(t, err)
	_, err = newTableRewrappingJob(context.Background(), nil, "someTable")
	require.Error(t, err)
	job, err := newTableRewrappingJob(context.Background(), kmsCache, "someTable")
	require.NoError(t, err)
	require.NotNil(t, job)
}
