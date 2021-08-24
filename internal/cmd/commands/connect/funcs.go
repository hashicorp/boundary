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
			"Credential Store ID":   crd.CredentialLibrary.CredentialStoreId,
			"Credential Library ID": crd.CredentialLibrary.Id,
			"Credential Store Type": crd.CredentialLibrary.Type,
		}
		if crd.CredentialLibrary.Name != "" {
			libMap["Credential Library Name"] = crd.CredentialLibrary.Name
		}
		if crd.CredentialLibrary.Description != "" {
			libMap["Credential Library Description"] = crd.CredentialLibrary.Description
		}
		maxLength := base.MaxAttributesLength(libMap, nil, nil)
		ret = append(ret,
			fmt.Sprintf("%sCredentials:", prefixString),
			base.WrapMap(2+prefixIndent, maxLength, libMap),
			fmt.Sprintf("%s  Secret:", prefixString))
		ret = append(ret,
			fmtSecretForTable(2+prefixIndent, crd)...,
		)
	}

	return ret
}

func fmtSecretForTable(indent int, sc *targets.SessionCredential) []string {
	prefixStr := strings.Repeat(" ", indent)
	origSecret := []string{fmt.Sprintf("%s    %s", prefixStr, sc.Secret.Raw)}
	switch sc.CredentialLibrary.Type {
	case "vault":
		in, err := base64.StdEncoding.DecodeString(strings.Trim(string(sc.Secret.Raw), `"`))
		if err != nil {
			return origSecret
		}
		dst := new(bytes.Buffer)
		if err := json.Indent(dst, in, fmt.Sprintf("%s    ", prefixStr), fmt.Sprintf("%s  ", prefixStr)); err != nil {
			return origSecret
		}
		secretStr := strings.Split(dst.String(), "\n")
		if len(secretStr) > 0 {
			secretStr[0] = fmt.Sprintf("%s    %s", prefixStr, secretStr[0])
		}
		return secretStr
	}
	return origSecret
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
