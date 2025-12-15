// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
)

func Test_AllRewrapTablesRegistered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	extWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, extWrapper)

	tables, err := kmsCache.ListDataKeyVersionReferencers(ctx)
	assert.NoError(t, err)

	var filteredTables []string
	// there are some tables we know won't be rewrapped
	for _, table := range tables {
		// oplog entries cannot be rewrapped at this time
		if table == "oplog_entry" {
			continue
		}
		// kms_data_key_version_destruction_job does not contain encrypted data, only a reference to the key versions
		if table == "kms_data_key_version_destruction_job" {
			continue
		}

		// all other tables should be registered
		filteredTables = append(filteredTables, table)
	}

	assert.Empty(t, cmp.Diff(filteredTables, kms.ListTablesSupportingRewrap(), cmpopts.SortSlices(func(i, j string) bool { return i < j })), "At least one table referencing a data key does not have a rewrapping function registered")
}
