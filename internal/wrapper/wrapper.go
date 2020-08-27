package wrapper

import (
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/shared-secure-libs/configutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
)

func GetWrapper(path, purpose string) (wrapping.Wrapper, error) {
	kmses, err := configutil.LoadConfigKMSes(path)
	if err != nil {
		return nil, fmt.Errorf("Error parsing config file: %w", err)
	}

	var kms *configutil.KMS
	for _, v := range kmses {
		if strutil.StrListContains(v.Purpose, purpose) {
			if kms != nil {
				return nil, fmt.Errorf("Only one %q block marked for %q purpose is allowed", "kms", purpose)
			}
			kms = v
		}
	}
	if kms == nil {
		return nil, nil
	}

	wrapper, err := configutil.ConfigureWrapper(kms, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error configuring kms: %w", err)
	}

	return wrapper, nil
}
