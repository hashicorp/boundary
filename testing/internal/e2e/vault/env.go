package vault

import "github.com/kelseyhightower/envconfig"

type config struct {
	VaultAddr  string `envconfig:"VAULT_ADDR" required:"true"` // e.g. "http://127.0.0.1:8200"
	VaultToken string `envconfig:"VAULT_TOKEN" required:"true"`
}

func loadConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
