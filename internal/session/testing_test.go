// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestSession(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	s := TestDefaultSession(t, conn, wrapper, iamRepo)
	require.NotNil(s)
	assert.NotEmpty(s.PublicId)
}

func Test_TestState(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	s := TestDefaultSession(t, conn, wrapper, iamRepo)
	require.NotNil(s)
	assert.NotEmpty(s.PublicId)

	state := TestState(t, conn, s.PublicId, StatusActive)
	require.NotNil(state)
}

func Test_TestConnection(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	s := TestDefaultSession(t, conn, wrapper, iamRepo)
	require.NotNil(s)
	assert.NotEmpty(s.PublicId)

	c := TestConnection(t, conn, s.PublicId, "127.0.0.1", 6500, "127.0.0.1", 22, "127.0.0.1")
	require.NotNil(c)
}

func Test_TestWorker(t *testing.T) {
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	w := server.TestKmsWorker(t, conn, wrapper)
	require.NotNil(w)
}

func Test_TestCert(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	sessionId, err := newId(context.Background())
	require.NoError(err)
	key, cert, err := TestCert(sessionId)
	require.NoError(err)
	assert.NotNil(key)
	assert.NotNil(cert)
}
