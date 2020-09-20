package proxy

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateConnectionInfoTableOutput(in ConnectionInfo) string {
	var ret []string

	nonAttributeMap := map[string]interface{}{
		"Protocol": in.Protocol,
		"Address":  in.Address,
		"Port":     in.Port,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret = append(ret, "", "Proxy listening information:")

	ret = append(ret,
		// We do +2 because there is another +2 offset for host sets below
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	)

	return base.WrapForHelpText(ret)
}
