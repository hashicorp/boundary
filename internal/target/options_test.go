// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeItem struct {
	pagination.Item
	publicId   string
	updateTime time.Time
}

func (p *fakeItem) GetPublicId() string {
	return p.publicId
}

func (p *fakeItem) GetUpdateTime() *timestamp.Timestamp {
	return timestamp.New(p.updateTime)
}

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithName", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.WithName = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.WithDescription = "test desc"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		assert := assert.New(t)
		// test default of 0
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.WithLimit = 0
		assert.Equal(opts, testOpts)

		opts = GetOpts(WithLimit(-1))
		testOpts = getDefaultOptions()
		testOpts.WithLimit = -1
		assert.Equal(opts, testOpts)

		opts = GetOpts(WithLimit(1))
		testOpts = getDefaultOptions()
		testOpts.WithLimit = 1
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDefaultPort", func(t *testing.T) {
		assert := assert.New(t)
		// test default of 0
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.WithDefaultPort = 0
		assert.Equal(opts, testOpts)

		opts = GetOpts(WithDefaultPort(22))
		testOpts = getDefaultOptions()
		testOpts.WithDefaultPort = uint32(22)
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDefaultClientPort", func(t *testing.T) {
		assert := assert.New(t)
		// test default of 0
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.WithDefaultClientPort = 0
		assert.Equal(opts, testOpts)

		opts = GetOpts(WithDefaultClientPort(22))
		testOpts = getDefaultOptions()
		testOpts.WithDefaultClientPort = uint32(22)
		assert.Equal(opts, testOpts)
	})
	t.Run("WithUserId", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithUserId("testId"))
		testOpts := getDefaultOptions()
		testOpts.WithUserId = "testId"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithProjectId", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithProjectId("testId"))
		testOpts := getDefaultOptions()
		testOpts.WithProjectId = "testId"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithProjectName", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithProjectName("testName"))
		testOpts := getDefaultOptions()
		testOpts.WithProjectName = "testName"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPublicId", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithPublicId("testId"))
		testOpts := getDefaultOptions()
		testOpts.WithPublicId = "testId"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithType", func(t *testing.T) {
		subtype := globals.Subtype("testtype")
		assert := assert.New(t)
		opts := GetOpts(WithType(subtype))
		testOpts := getDefaultOptions()
		target := subtype
		testOpts.WithType = target
		assert.Equal(opts, testOpts)
	})
	t.Run("WithHostSources", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithHostSources([]string{"alice", "bob"}))
		testOpts := getDefaultOptions()
		testOpts.WithHostSources = []string{"alice", "bob"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithWorkerFilter", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithWorkerFilter(`"/foo" == "bar"`))
		testOpts := getDefaultOptions()
		testOpts.WithWorkerFilter = `"/foo" == "bar"`
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTestWorkerFilter", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithTestWorkerFilter(`"/foo" == "bar"`))
		testOpts := getDefaultOptions()
		testOpts.WithTestWorkerFilter = `"/foo" == "bar"`
		assert.Equal(opts, testOpts)
	})
	t.Run("WithEgressWorkerFilter", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithEgressWorkerFilter(`"/foo" == "bar"`))
		testOpts := getDefaultOptions()
		testOpts.WithEgressWorkerFilter = `"/foo" == "bar"`
		assert.Equal(opts, testOpts)
	})
	t.Run("WithIngressWorkerFilter", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithIngressWorkerFilter(`"/foo" == "bar"`))
		testOpts := getDefaultOptions()
		testOpts.WithIngressWorkerFilter = `"/foo" == "bar"`
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPermissions", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithPermissions([]perms.Permission{{GrantScopeId: "test1"}, {GrantScopeId: "test2"}}))
		testOpts := getDefaultOptions()
		testOpts.WithPermissions = []perms.Permission{{GrantScopeId: "test1"}, {GrantScopeId: "test2"}}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithCredentialLibraries", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithCredentialLibraries([]*CredentialLibrary{
			{
				CredentialLibrary: &store.CredentialLibrary{
					CredentialLibraryId: "alice",
					CredentialPurpose:   string(credential.BrokeredPurpose),
				},
			},
			{
				CredentialLibrary: &store.CredentialLibrary{
					CredentialLibraryId: "bob",
					CredentialPurpose:   string(credential.InjectedApplicationPurpose),
				},
			},
		}))
		testOpts := getDefaultOptions()
		testOpts.WithCredentialLibraries = []*CredentialLibrary{
			{
				CredentialLibrary: &store.CredentialLibrary{
					CredentialLibraryId: "alice",
					CredentialPurpose:   string(credential.BrokeredPurpose),
				},
			},
			{
				CredentialLibrary: &store.CredentialLibrary{
					CredentialLibraryId: "bob",
					CredentialPurpose:   string(credential.InjectedApplicationPurpose),
				},
			},
		}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithStaticCredentials", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithStaticCredentials([]*StaticCredential{
			{
				StaticCredential: &store.StaticCredential{
					CredentialId:      "alice",
					CredentialPurpose: string(credential.BrokeredPurpose),
				},
			},
			{
				StaticCredential: &store.StaticCredential{
					CredentialId:      "bob",
					CredentialPurpose: string(credential.InjectedApplicationPurpose),
				},
			},
		}))
		testOpts := getDefaultOptions()
		testOpts.WithStaticCredentials = []*StaticCredential{
			{
				StaticCredential: &store.StaticCredential{
					CredentialId:      "alice",
					CredentialPurpose: string(credential.BrokeredPurpose),
				},
			},
			{
				StaticCredential: &store.StaticCredential{
					CredentialId:      "bob",
					CredentialPurpose: string(credential.InjectedApplicationPurpose),
				},
			},
		}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithStorageBucketId", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithStorageBucketId("testId"))
		testOpts := getDefaultOptions()
		testOpts.WithStorageBucketId = "testId"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithEnableSessionRecording", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithEnableSessionRecording(true))
		testOpts := getDefaultOptions()
		testOpts.WithEnableSessionRecording = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithStartPageAfterItem", func(t *testing.T) {
		assert := assert.New(t)
		updateTime := time.Now()
		opts := GetOpts(WithStartPageAfterItem(&fakeItem{nil, "s_1", updateTime}))
		assert.Equal(opts.WithStartPageAfterItem.GetPublicId(), "s_1")
		assert.Equal(opts.WithStartPageAfterItem.GetUpdateTime(), timestamp.New(updateTime))
	})
	t.Run("WithAliases", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		al, err := talias.NewAlias(context.Background(), "global", "test")
		require.NoError(err)
		input := []*talias.Alias{al}
		opts := GetOpts(WithAliases(input))
		assert.Equal(input, opts.withAliases)
	})
	t.Run("WithAlias", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		al, err := talias.NewAlias(context.Background(), "global", "test")
		require.NoError(err)
		opts := GetOpts(WithAlias(al))
		assert.Equal(al, opts.WithAlias)
	})
	t.Run("WithTargetId", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithTargetId("testId"))
		testOpts := getDefaultOptions()
		testOpts.withTargetId = "testId"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRandomReader", func(t *testing.T) {
		assert := assert.New(t)
		reader := strings.NewReader("notrandom")
		opts := GetOpts(WithRandomReader(reader))
		testOpts := getDefaultOptions()
		testOpts.withRandomReader = reader
		assert.Equal(opts, testOpts)
	})
}
