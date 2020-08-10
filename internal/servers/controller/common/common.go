package common

import (
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
)

type (
	IamRepoFactory          func() (*iam.Repository, error)
	StaticRepoFactory       func() (*static.Repository, error)
	AuthTokenRepoFactory    func() (*authtoken.Repository, error)
	PasswordAuthRepoFactory func() (*password.Repository, error)
)
