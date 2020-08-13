package controller

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/servers/controller"
)

func getOpts(opt ...Option) (*controller.TestControllerOpts, error) {
	opts := &option{
		tcOptions: &controller.TestControllerOpts{},
	}
	for _, o := range opt {
		if err := o(opts); err != nil {
			return nil, err
		}
	}
	if opts.setWithConfigFile && opts.setWithConfigText {
		return nil, fmt.Errorf("Cannot provide both WithConfigFile and WithConfigText")
	}
	return opts.tcOptions, nil
}

type option struct {
	tcOptions                  *controller.TestControllerOpts
	setWithConfigFile          bool
	setWithConfigText          bool
	setDisableDatabaseCreation bool
	setDefaultOrgId            bool
	setDefaultAuthMethodId     bool
	setDefaultLoginName        bool
	setDefaultPassword         bool
}

type Option func(*option) error

// WithConfigFile provides the given ConfigFile to the built TestController.
// This option cannot be used if WithConfigText is used.
func WithConfigFile(f string) Option {
	return func(c *option) error {
		if c.setWithConfigFile {
			return fmt.Errorf("WithConfigFile provided more than once.")
		}
		c.setWithConfigFile = true
		cfg, err := config.LoadFile(f, nil)
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

// DisableDatabaseCreation skips creating a database in docker and allows one to
// be provided through a tcOptions.
func DisableDatabaseCreation() Option {
	return func(c *option) error {
		if c.setDisableDatabaseCreation {
			return fmt.Errorf("DisableDatabaseCreation provided more than once.")
		}
		c.setDisableDatabaseCreation = true
		c.tcOptions.DisableDatabaseCreation = true
		return nil
	}
}

// WithDefaultOrgId sets the org id to the one provided here.
func WithDefaultOrgId(id string) Option {
	return func(c *option) error {
		if c.setDefaultOrgId {
			return fmt.Errorf("WithDefaultOrgId provided more than once.")
		}
		c.setDefaultOrgId = true
		c.tcOptions.DefaultOrgId = id
		return nil
	}
}

func WithDefaultAuthMethodId(id string) Option {
	return func(c *option) error {
		if c.setDefaultAuthMethodId {
			return fmt.Errorf("WithDefaultAuthMethodId provided more than once.")
		}
		c.setDefaultAuthMethodId = true
		c.tcOptions.DefaultAuthMethodId = id
		return nil
	}
}

func WithDefaultLoginName(ln string) Option {
	return func(c *option) error {
		if c.setDefaultLoginName {
			return fmt.Errorf("WithDefaultLoginName provided more than once.")
		}
		c.setDefaultLoginName = true
		c.tcOptions.DefaultLoginName = ln
		return nil
	}
}

func WithDefaultPassword(pw string) Option {
	return func(c *option) error {
		if c.setDefaultPassword {
			return fmt.Errorf("WithDefaultPassword provided more than once.")
		}
		c.setDefaultPassword = true
		c.tcOptions.DefaultPassword = pw
		return nil
	}
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

type TestController struct {
	*controller.TestController
}
