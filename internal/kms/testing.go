package kms

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

func TestExternalConfig(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, scopeId string, confType KmsType, conf string) *ExternalConfig {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	config, err := NewExternalConfig(scopeId, confType, conf)
	require.NoError(err)
	id, err := newExternalConfigId()
	require.NoError(err)
	config.PrivateId = id
	err = config.encrypt(context.Background(), wrapper)
	require.NoError(err)
	err = rw.Create(context.Background(), config)
	require.NoError(err)
	require.Equal(conf, config.Config)
	return config
}

func TestRootKey(t *testing.T, conn *gorm.DB, scopeId string) *RootKey {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	k, err := NewRootKey(scopeId)
	require.NoError(err)
	id, err := newRootKeyId()
	require.NoError(err)
	k.PrivateId = id
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestRootKeyVersion(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, rootId, key string) *RootKeyVersion {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	k, err := NewRootKeyVersion(rootId, key)
	require.NoError(err)
	id, err := newRootKeyVersionId()
	require.NoError(err)
	k.PrivateId = id
	err = k.encrypt(context.Background(), wrapper)
	require.NoError(err)
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}
