package common

import (
	"github.com/hashicorp/watchtower/internal/auth/password"
	"github.com/hashicorp/watchtower/internal/authtoken"
	"github.com/hashicorp/watchtower/internal/host/static"
	"github.com/hashicorp/watchtower/internal/iam"
)

type (
	IamRepoFactory          func() (*iam.Repository, error)
	StaticRepoFactory       func() (*static.Repository, error)
	AuthTokenRepoFactory    func() (*authtoken.Repository, error)
	PasswordAuthRepoFactory func() (*password.Repository, error)
)
