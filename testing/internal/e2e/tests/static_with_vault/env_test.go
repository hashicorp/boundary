package static_with_vault_test

import "github.com/kelseyhightower/envconfig"

type config struct {
	TargetIp         string `envconfig:"E2E_TARGET_IP" required:"true"`    // e.g. 192.168.0.1
	TargetSshUser    string `envconfig:"E2E_SSH_USER" required:"true"`     // e.g. ubuntu
	TargetSshKeyPath string `envconfig:"E2E_SSH_KEY_PATH" required:"true"` // e.g. /Users/username/key.pem
	TargetPort       string `envconfig:"E2E_SSH_PORT" default:"22"`
	VaultSecretPath  string `envconfig:"E2E_VAULT_SECRET_PATH" default:"e2e_secrets"`
}

func loadConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
