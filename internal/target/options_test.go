package target

import (
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	"github.com/stretchr/testify/assert"
)

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
		subtype := subtypes.Subtype("testtype")
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
}
