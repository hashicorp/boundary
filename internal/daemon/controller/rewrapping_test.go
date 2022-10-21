package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
)

func SliceContains(slice []string, item string) bool {
	for _, i := range slice {
		if item == i {
			return true
		}
	}
	return false
}

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
		// kms_data_key_version_destruction_job does not contain encrypte data, only a reference to the key versions
		if table == "kms_data_key_version_destruction_job" {
			continue
		}

		// all other tables should be registered
		filteredTables = append(filteredTables, table)
	}

	registeredTables := kms.ListTablesSupportingRewrap()

	// first things first, make sure we have the same number of expected values.
	assert.Equal(t, len(filteredTables), len(registeredTables), "the number of registered rewrap functions does not match the number of tables that contain encrypted data.")

	// then make sure that all of the tables that need rewrap funcs registered actually have them.
	for _, table := range filteredTables {
		// do this in a loop so that we can explicitly call out which tables are missing, if any are.
		assert.True(t, SliceContains(registeredTables, table), fmt.Sprintf("%s doesn't have a rewrap function registered!", table))
	}
}
