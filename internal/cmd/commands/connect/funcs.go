// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/mapstructure"
)

func generateSessionInfoTableOutput(in SessionInfo) string {
	nonAttributeMap := map[string]any{
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

	if len(creds) > 0 {
		// Add credential header
		ret = append(ret, fmt.Sprintf("%sCredentials:", prefixString))
	}
	for _, crd := range creds {
		credMap := map[string]any{
			"Credential Store ID":   crd.CredentialSource.CredentialStoreId,
			"Credential Source ID":  crd.CredentialSource.Id,
			"Credential Store Type": crd.CredentialSource.Type,
		}
		if crd.CredentialSource.Name != "" {
			credMap["Credential Source Name"] = crd.CredentialSource.Name
		}
		if crd.CredentialSource.Description != "" {
			credMap["Credential Source Description"] = crd.CredentialSource.Description
		}
		if crd.CredentialSource.CredentialType != "" {
			credMap["Credential Type"] = crd.CredentialSource.CredentialType
		}
		maxLength := base.MaxAttributesLength(credMap, nil, nil)
		ret = append(ret,
			base.WrapMap(2+prefixIndent, maxLength, credMap),
			fmt.Sprintf("%s  Secret:", prefixString))
		ret = append(ret,
			fmtSecretForTable(2+prefixIndent, crd)...,
		)
		ret = append(ret, "")
	}

	return ret
}

func fmtSecretForTable(indent int, sc *targets.SessionCredential) []string {
	prefixStr := strings.Repeat(" ", indent)
	origSecret := []string{fmt.Sprintf("%s    %s", prefixStr, sc.Secret.Raw)}
	if sc.Credential != nil {
		maxLength := 0
		for k := range sc.Credential {
			if len(k) > maxLength {
				maxLength = len(k)
			}
		}
		return []string{fmt.Sprintf("%s    %s", prefixStr, base.WrapMap(2, maxLength+2, sc.Credential))}
	}

	in, err := base64.StdEncoding.DecodeString(strings.Trim(string(sc.Secret.Raw), `"`))
	if err != nil {
		return origSecret
	}

	// The following operations are performed to better format unspecified credential types.
	// Credential values (with the exception of Vault metadata) are printed with no indentation
	// so that X.509 certificates can be easily copied and pasted by the user.
	var out []string
	var baseCredMap map[string]any
	mdMap := make(map[string]any)
	err = json.Unmarshal(in, &baseCredMap)
	if err != nil {
		return origSecret
	}
	for k, iface := range baseCredMap {

		// Treat the Vault credential metadata as an exception case, to apply the better-looking
		// base.WrapMap formatting.
		if k == "metadata" {
			md := make(map[string]any)
			if err := mapstructure.Decode(iface, &md); err != nil {
				// Return a best-effort representation of the metadata if it is
				// unable to be decoded.
				mdMap[k] = iface
				continue
			}
			mdMap[k] = md
			continue
		}

		// Print all other credential fields with no spacing for the values
		switch iface := iface.(type) {
		case nil:
			out = append(out, fmt.Sprintf("%s    %s:", prefixStr, k))
		case map[string]string:
			out = append(out, fmt.Sprintf("%s    %s:", prefixStr, k))
			for kk, vv := range iface {
				out = append(out, fmt.Sprintf("%s      %s:", prefixStr, kk))
				out = append(out, fmt.Sprintf("%s\n", vv))
			}
		case map[string]any:
			// TODO: check if this is the only possible case for an 'unspecified' type credential
			// and get rid of the other cases if this is so.
			out = append(out, fmt.Sprintf("%s    %s:", prefixStr, k))
			for kk, vv := range iface {
				out = append(out, fmt.Sprintf("%s      %s:", prefixStr, kk))
				out = append(out, fmt.Sprintf("%v\n", vv))
			}
		default:
			out = append(out, fmt.Sprintf("%s    %s:", prefixStr, k))
			out = append(out, fmt.Sprintf("%v\n", iface))
		}
	}

	for k, v := range mdMap {
		out = append(out, fmt.Sprintf("%s    %s:", prefixStr, k))
		out = append(out, base.WrapMap(indent+6, 0, v.(map[string]any)))
	}

	return out
}

func generateConnectionInfoTableOutput(in ConnectionInfo) string {
	var ret []string

	nonAttributeMap := map[string]any{
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

	nonAttributeMap := map[string]any{
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
