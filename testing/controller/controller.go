// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"

	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
)

type option struct {
	tcOptions                      *controller.TestControllerOpts
	setWithConfigFile              bool
	setWithConfigText              bool
	setDisableAuthMethodCreation   bool
	setDisableDatabaseCreation     bool
	setDisableDatabaseDestruction  bool
	setDefaultPasswordAuthMethodId bool
	setDefaultOidcAuthMethodId     bool
	setDefaultLdapAuthMethodId     bool
	setDefaultLoginName            bool
	setDefaultPassword             bool
	setRootKms                     bool
	setWorkerAuthKms               bool
	setRecoveryKms                 bool
	setDatabaseUrl                 bool
	setEnableTemplatedDatabase     bool
	setEnableEventing              bool
}

type Option func(*option) error

func getOpts(opt ...Option) (*controller.TestControllerOpts, error) {
	opts := &option{
		tcOptions: &controller.TestControllerOpts{},
	}
	for _, o := range opt {
		if err := o(opts); err != nil {
			return nil, err
		}
	}
	opts.tcOptions.DisableDatabaseTemplate = !opts.setEnableTemplatedDatabase
	if opts.setWithConfigFile && opts.setWithConfigText {
		return nil, fmt.Errorf("Cannot provide both WithConfigFile and WithConfigText")
	}
	var setDbParams bool
	if opts.setDefaultPasswordAuthMethodId ||
		opts.setDefaultOidcAuthMethodId ||
		opts.setDefaultLdapAuthMethodId ||
		opts.setDefaultLoginName ||
		opts.setDefaultPassword {
		setDbParams = true
	}
	if opts.setDisableAuthMethodCreation {
		if setDbParams {
			return nil, fmt.Errorf("Cannot both disable auth method creation and provide auth method parameters")
		}
	}
	if opts.setDisableDatabaseCreation {
		if setDbParams {
			return nil, fmt.Errorf("Cannot both disable database creation and provide auth method parameters")
		}
	}
	return opts.tcOptions, nil
}

// WithConfigFile provides the given ConfigFile to the built TestController.
// This option cannot be used if WithConfigText is used.
func WithConfigFile(f string) Option {
	return func(c *option) error {
		if c.setWithConfigFile {
			return fmt.Errorf("WithConfigFile provided more than once.")
		}
		c.setWithConfigFile = true
		cfg, err := config.Load(context.Background(), []string{f}, "")
		if err != nil {
			return err
		}
		c.tcOptions.Config = cfg
		return nil
	}
}

// WithConfigText configures the TestController sets up the Controller using the
// provided config text. This option cannot be used if WithConfigFile is used.
func WithConfigText(ct string) Option {
	return func(c *option) error {
		if c.setWithConfigText {
			return fmt.Errorf("WithConfigText provided more than once.")
		}
		c.setWithConfigText = true
		cfg, err := config.Parse(ct)
		if err != nil {
			return err
		}
		c.tcOptions.Config = cfg
		return nil
	}
}

// DisableAuthMethodCreation skips creating a default auth method
func DisableAuthMethodCreation() Option {
	return func(c *option) error {
		c.setDisableAuthMethodCreation = true
		c.tcOptions.DisableAuthMethodCreation = true
		return nil
	}
}

// DisableDatabaseCreation skips creating a database in docker and allows one to
// be provided through a tcOptions.
func DisableDatabaseCreation() Option {
	return func(c *option) error {
		c.setDisableDatabaseCreation = true
		c.tcOptions.DisableDatabaseCreation = true
		return nil
	}
}

// DisableDatabaseCreation skips creating a database in docker and allows one to
// be provided through a tcOptions.
func DisableDatabaseDestruction() Option {
	return func(c *option) error {
		c.setDisableDatabaseDestruction = true
		c.tcOptions.DisableDatabaseDestruction = true
		return nil
	}
}

func WithDefaultPasswordAuthMethodId(id string) Option {
	return func(c *option) error {
		c.setDefaultPasswordAuthMethodId = true
		c.tcOptions.DefaultPasswordAuthMethodId = id
		return nil
	}
}

func WithDefaultOidcAuthMethodId(id string) Option {
	return func(c *option) error {
		c.setDefaultOidcAuthMethodId = true
		c.tcOptions.DefaultOidcAuthMethodId = id
		return nil
	}
}

func WithDefaultLdapAuthMethodId(id string) Option {
	return func(c *option) error {
		c.setDefaultLdapAuthMethodId = true
		c.tcOptions.DefaultLdapAuthMethodId = id
		return nil
	}
}

func WithDefaultLoginName(ln string) Option {
	return func(c *option) error {
		c.setDefaultLoginName = true
		c.tcOptions.DefaultLoginName = ln
		return nil
	}
}

func WithDefaultPassword(pw string) Option {
	return func(c *option) error {
		c.setDefaultPassword = true
		c.tcOptions.DefaultPassword = pw
		return nil
	}
}

func WithRootKms(wrapper wrapping.Wrapper) Option {
	return func(c *option) error {
		c.setRootKms = true
		c.tcOptions.RootKms = wrapper
		return nil
	}
}

func WithWorkerAuthKms(wrapper wrapping.Wrapper) Option {
	return func(c *option) error {
		c.setWorkerAuthKms = true
		c.tcOptions.WorkerAuthKms = wrapper
		return nil
	}
}

func WithRecoveryKms(wrapper wrapping.Wrapper) Option {
	return func(c *option) error {
		c.setRecoveryKms = true
		c.tcOptions.RecoveryKms = wrapper
		return nil
	}
}

func WithDatabaseUrl(url string) Option {
	return func(c *option) error {
		c.setDatabaseUrl = true
		c.tcOptions.DatabaseUrl = url
		return nil
	}
}

// WithEnableTemplatedDatabase enables usage of a local database test instance
// with a template. Generally outside tests will probably want to use the
// non-templated database, so this defaults to enabling instead of disabling.
func WithEnableTemplatedDatabase(enable bool) Option {
	return func(c *option) error {
		c.setEnableTemplatedDatabase = enable
		return nil
	}
}

func WithEnableEventing() Option {
	return func(c *option) error {
		c.setEnableEventing = true
		c.tcOptions.EnableEventing = true
		return nil
	}
}

type TestController struct {
	*controller.TestController
}

// NewTestController blocks until a new TestController is created, returns the url for the TestController and a function
// that can be called to tear down the controller after it has been used for testing.
func NewTestController(t *testing.T, opt ...Option) *TestController {
	conf, err := getOpts(opt...)
	if err != nil {
		t.Fatalf("Couldn't create TestController: %v", err)
	}
	tc := controller.NewTestController(t, conf)
	return &TestController{TestController: tc}
}
