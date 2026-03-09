// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/boundary/api"
)

func writeError(w http.ResponseWriter, msg string, s int) {
	status := http.StatusText(s)
	b, err := json.Marshal(&api.Error{
		Kind:    status,
		Message: msg,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Unable to marshal error {Kind: %s, Message: %q} into api error format: %s", status, msg, err.Error()), http.StatusInternalServerError)
		return
	}
	http.Error(w, string(b), s)
}
