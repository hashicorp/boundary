package kms

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

func TestExternalConfig(t *testing.T, conn *gorm.DB, scopeId, confType, conf string) *ExternalConfig {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	config, err := NewExternalConfig(scopeId, confType, conf)
	require.NoError(err)
	id, err := newExternalConfigId()
	require.NoError(err)
	config.PrivateId = id
	err = rw.Create(context.Background(), config)
	require.NoError(err)
	require.Equal(conf, config.Config)
	return config
}
