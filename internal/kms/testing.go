package kms

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func testOrg(t *testing.T, conn *gorm.DB) (org *iam.Scope) {
	t.Helper()
	assert := assert.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := iam.NewRepository(rw, rw, wrapper)
	assert.NoError(err)

	o, err := iam.NewOrganization()
	assert.NoError(err)
	o, err = repo.CreateScope(context.Background(), o)
	assert.NoError(err)
	assert.NotNil(o)
	assert.NotEmpty(o.GetPublicId())
	return o
}
func testId(t *testing.T) string {
	id, err := uuid.GenerateUUID()
	assert.NoError(t, err)
	return id
}
func testKeyEntry(t *testing.T, conn *gorm.DB, orgId, keyId string, key []byte) *KeyEntry {
	assert := assert.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(err)

	entry, err := NewKeyEntry(orgId, keyId, key)
	assert.NoError(err)

	createdEntry, err := repo.CreateKeyEntry(context.Background(), entry)
	assert.NoError(err)
	return createdEntry

}
