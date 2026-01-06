// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"testing"
)

func AuthenticateHttp(t testing.TB, ctx context.Context, address, authMethodId, loginName, password string) (*http.Response, error) {
	requestURL := fmt.Sprintf("%s/v1/auth-methods/%s:authenticate", address, authMethodId)
	jsonBody := []byte(
		fmt.Sprintf(`{"command":"login", "type":null, "attributes":{"login_name":"%s","password":"%s"}}`,
			loginName,
			password,
		),
	)
	bodyReader := bytes.NewReader(jsonBody)
	req, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return res, err
	}

	return res, nil
}
