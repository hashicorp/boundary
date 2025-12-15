// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentialstores

import (
	"context"
	"encoding/pem"
	"testing"

	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPkAndClientCerts(t *testing.T) {
	ctx := context.Background()
	s := vault.NewTestVaultServer(t, vault.WithTestVaultTLS(vault.TestClientTLS))

	t.Run("separate client cert and key", func(t *testing.T) {
		c, k, err := extractClientCertAndPk(ctx, string(s.ClientCert), string(s.ClientKey))
		assert.NoError(t, err)
		require.NotNil(t, k)
		assert.Equal(t, s.ClientKey, pem.EncodeToMemory(k))
		require.Len(t, c, 1)
		assert.Equal(t, s.ClientCert, pem.EncodeToMemory(c[0]))
	})

	t.Run("client cert and key bundled in cert", func(t *testing.T) {
		c, k, err := extractClientCertAndPk(ctx, string(s.ClientCert)+string(s.ClientKey), "")
		assert.NoError(t, err)
		require.NotNil(t, k)
		assert.Equal(t, s.ClientKey, pem.EncodeToMemory(k))
		require.Len(t, c, 1)
		assert.Equal(t, s.ClientCert, pem.EncodeToMemory(c[0]))
	})

	t.Run("cert with no private key", func(t *testing.T) {
		c, k, err := extractClientCertAndPk(ctx, string(s.ClientCert), "")
		assert.NoError(t, err)
		assert.Nil(t, k)
		require.Len(t, c, 1)
		assert.Equal(t, s.ClientCert, pem.EncodeToMemory(c[0]))
	})

	t.Run("private key with no cert", func(t *testing.T) {
		c, k, err := extractClientCertAndPk(ctx, "", string(s.ClientKey))
		assert.NoError(t, err)
		assert.NotNil(t, k)
		assert.Equal(t, s.ClientKey, pem.EncodeToMemory(k))
		require.Empty(t, c)
	})

	t.Run("error cases", func(t *testing.T) {
		_, _, err := extractClientCertAndPk(ctx, string(s.ClientCert), "invalid key")
		assert.Error(t, err)
		_, _, err = extractClientCertAndPk(ctx, "invalid cert", string(s.ClientKey))
		assert.Error(t, err)

		// private key with the cert and the private key
		c, k, err := extractClientCertAndPk(ctx, string(s.ClientCert)+string(s.ClientKey), string(s.ClientKey))
		assert.Error(t, err)
		assert.Nil(t, k)
		assert.Empty(t, c)
	})
}
