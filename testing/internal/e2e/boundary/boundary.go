// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package boundary provides methods for commonly used boundary actions that are used in end-to-end tests.
package boundary

import (
	"github.com/hashicorp/boundary/api/authmethods"
)

// ConnectCliOutput parses the json response from running `boundary connect`
type ConnectCliOutput struct {
	Port    int    `json:"port"`
	Address string `json:"address"`
}

// AuthenticateCliOutput parses the json response from running `boundary authenticate`
type AuthenticateCliOutput struct {
	Item       *authmethods.AuthenticateResult
	StatusCode int `json:"status_code"`
}

// AuthMethodInfo parses auth method info in the json response from running `boundary database init`
type AuthMethodInfo struct {
	AuthMethodId string `json:"auth_method_id"`
	LoginName    string `json:"login_name"`
	Password     string `json:"password"`
}

// DbInitInfo parses the json response from running `boundary database init`
type DbInitInfo struct {
	AuthMethod AuthMethodInfo `json:"auth_method"`
}

// CliError parses the Stderr from running a boundary command
type CliError struct {
	Status int `json:"status"`
}
