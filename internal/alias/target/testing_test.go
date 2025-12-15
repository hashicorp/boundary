// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target_test

import (
	"context"
	"testing"

	atar "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
)

func TestTestAlias(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	tar := tcp.TestTarget(context.Background(), t, conn, proj.GetPublicId(), "test target")

	a := atar.TestAlias(t, rw, "example.alias",
		atar.WithDescription("description"),
		atar.WithName("name"),
		atar.WithDestinationId(tar.GetPublicId()),
		atar.WithHostId("hst_1234567890"))

	assert.Equal(t, "example.alias", a.GetValue())
	assert.Equal(t, "description", a.GetDescription())
	assert.Equal(t, "name", a.GetName())
	assert.Equal(t, tar.GetPublicId(), a.GetDestinationId())
	assert.Equal(t, "hst_1234567890", a.GetHostId())
	assert.Equal(t, "global", a.GetScopeId())
	assert.NotEmpty(t, a.GetPublicId())
}
