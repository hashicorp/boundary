package common

import (
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/credential/vault"
	pluginhost "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
)

type (
	AuthTokenRepoFactory       = oidc.AuthTokenRepoFactory
	VaultCredentialRepoFactory = func() (*vault.Repository, error)
	IamRepoFactory             func() (*iam.Repository, error)
	OidcAuthRepoFactory        = oidc.OidcRepoFactory
	PasswordAuthRepoFactory    func() (*password.Repository, error)
	ServersRepoFactory         func() (*servers.Repository, error)
	StaticRepoFactory          func() (*static.Repository, error)
	PluginHostRepoFactory      func() (*pluginhost.Repository, error)
	HostPluginRepoFactory      func() (*hostplugin.Repository, error)
	SessionRepoFactory         func() (*session.Repository, error)
	ConnectionRepoFactory      func() (*session.ConnectionRepository, error)
	TargetRepoFactory          func() (*target.Repository, error)
)
