package common

import (
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	credstatic "github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	pluginhost "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
)

type (
	AuthTokenRepoFactory         = oidc.AuthTokenRepoFactory
	VaultCredentialRepoFactory   = func() (*vault.Repository, error)
	StaticCredentialRepoFactory  = func() (*credstatic.Repository, error)
	IamRepoFactory               = iam.IamRepoFactory
	OidcAuthRepoFactory          = oidc.OidcRepoFactory
	LdapAuthRepoFactory          = ldap.RepoFactory
	PasswordAuthRepoFactory      func() (*password.Repository, error)
	ServersRepoFactory           func() (*server.Repository, error)
	StaticRepoFactory            func() (*static.Repository, error)
	PluginHostRepoFactory        func() (*pluginhost.Repository, error)
	HostPluginRepoFactory        func() (*hostplugin.Repository, error)
	ConnectionRepoFactory        func() (*session.ConnectionRepository, error)
	WorkerAuthRepoStorageFactory func() (*server.WorkerAuthRepositoryStorage, error)
)

// Downstreamers provides at least a minimum interface that must be met by a
// Controller.downstreamWorkers field which is far better than allowing any (empty
// interface)
type Downstreamers interface {
	// RootId returns the root ID of the downstreamers' graph
	RootId() string
}
