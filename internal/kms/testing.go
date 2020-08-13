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
