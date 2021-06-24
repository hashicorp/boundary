package connect

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api/targets"
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
	if len(in.Credentials) > 0 {
		ret = append(ret,
			"")
		ret = append(ret,
			generateCredentialTableOutputSlice(2, in.Credentials)...)
	}

	return base.WrapForHelpText(ret)
}

func generateCredentialTableOutput(creds []*targets.SessionCredential) string {
	return base.WrapForHelpText(generateCredentialTableOutputSlice(0, creds))
}

func generateCredentialTableOutputSlice(prefixIndent int, creds []*targets.SessionCredential) []string {
	var ret []string
	prefixString := strings.Repeat(" ", prefixIndent)
	for _, crd := range creds {
		libMap := map[string]interface{}{
			"Credential Store ID:":  crd.CredentialLibrary.CredentialStoreId,
			"Credential Library ID": crd.CredentialLibrary.Id,
			"Credential Store Type": crd.CredentialLibrary.Type,
			"Purpose":               crd.Purpose,
		}
		if crd.CredentialLibrary.Name != "" {
			libMap["Credential Library Name"] = crd.CredentialLibrary.Name
		}
		if crd.CredentialLibrary.Description != "" {
			libMap["Credential Library Description"] = crd.CredentialLibrary.Description
		}
		maxLength := base.MaxAttributesLength(libMap, nil, nil)
		ret = append(ret,
			fmt.Sprintf("%sCredential:", prefixString),
			base.WrapMap(2 + prefixIndent, maxLength, libMap),
			fmt.Sprintf("%s  Secret:", prefixString),
			fmtSecretForTable(2 + prefixIndent, crd),
		)
	}

	return ret
}

func fmtSecretForTable(indent int, sc *targets.SessionCredential) string {
	switch sc.CredentialLibrary.Type {
	case "vault":
		// If it's Vault, the result will be JSON, except in
		// specific circumstances that aren't used for
		// credential fetching. So we can take the bytes
		// as-is (after base64-decoding)
		in, err := base64.StdEncoding.DecodeString(sc.Secret)
		if err != nil {
			return sc.Secret
		}
		dst := new(bytes.Buffer)
		if err := json.Indent(dst, in, strings.Repeat(" ", indent)+"      ", strings.Repeat(" ", indent)+"  "); err != nil {
			return sc.Secret
		}
		secretStr := strings.Split(dst.String(), "\n")
		if len(secretStr) > 0 {
			// Indent doesn't apply to the first line 🙄
			secretStr[0] = fmt.Sprintf("      %s", secretStr[0])
		}
		return strings.Join(secretStr, "\n")
	default:
		// If we don't know the type of the backing secrets engine we'll pass
		// the data on w/o decoding.
	}
	return sc.Secret
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
