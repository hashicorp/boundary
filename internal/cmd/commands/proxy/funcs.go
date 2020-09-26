package proxy

import (
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateSessionInfoTableOutput(in SessionInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Session ID":       in.SessionId,
		"Protocol":         in.Protocol,
		"Address":          in.Address,
		"Port":             in.Port,
		"Expiration":       in.Expiration.Local().Format(time.RFC1123),
		"Connection Limit": in.ConnectionLimit,
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Proxy listening information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	return base.WrapForHelpText(ret)
}

func generateConnectionInfoTableOutput(in ConnectionInfo) string {
	var ret []string

	nonAttributeMap := map[string]interface{}{
		"Connections Left": in.ConnectionsLeft,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret = append(ret, "", "Connection information:")

	ret = append(ret,
		// We do +2 because there is another +2 offset for host sets below
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	)

	return base.WrapForHelpText(ret)
}

func generateTerminationInfoTableOutput(in TerminationInfo) string {
	var ret []string

	nonAttributeMap := map[string]interface{}{
		"Reason": in.Reason,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret = append(ret, "", "Termination information:")

	ret = append(ret,
		// We do +2 because there is another +2 offset for host sets below
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	)

	return base.WrapForHelpText(ret)
}
