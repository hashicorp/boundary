// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package job

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/stretchr/testify/require"
)

func Test_RegisterJobs(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	extWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, extWrapper)
	s := scheduler.TestScheduler(t, conn, extWrapper)

	err := RegisterJobs(context.Background(), nil, nil)
	require.Error(t, err)
	err = RegisterJobs(context.Background(), s, nil)
	require.Error(t, err)
	err = RegisterJobs(context.Background(), nil, kmsCache)
	require.Error(t, err)
	err = RegisterJobs(context.Background(), s, kmsCache)
	require.NoError(t, err)
}
