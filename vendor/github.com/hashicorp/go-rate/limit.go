// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package rate

import (
	"fmt"
	"time"
)

// LimitPer identifies how a limit is allocated.
type LimitPer string

func (p LimitPer) String() string {
	return string(p)
}

// IsValid checks if the given LimitPer is valid.
func (p LimitPer) IsValid() bool {
	switch p {
	case LimitPerTotal, LimitPerIPAddress, LimitPerAuthToken:
		return true
	}
	return false
}

const (
	// LimitPerIPAddress indicates that the limit applies per IP address.
	LimitPerIPAddress LimitPer = "ip-address"
	// LimitPerAuthToken indicates that the limit applies per auth token.
	LimitPerAuthToken LimitPer = "auth-token"
	// LimitPerTotal indicates that the limit applies for all IP address and all Auth Tokens.
	LimitPerTotal LimitPer = "total"
)

// Limit defines the number of requests that can be made to perform an action
// against a resource in a time period, allocated per IP address, auth token,
// or in total. A Limit is either Limited or Unlimited.
type Limit interface {
	// GetResource returns the resource.
	GetResource() string
	// GetAction returns the action.
	GetAction() string
	// GetPer returns the LimitPer.
	GetPer() LimitPer

	validate() error
}

// Limited is a Limit that defines the maximum number of requests that can be
// made in a given time period.
type Limited struct {
	Action   string
	Resource string
	Per      LimitPer

	MaxRequests uint64
	Period      time.Duration
}

func (l *Limited) GetResource() string { return l.Resource }
func (l *Limited) GetAction() string   { return l.Action }
func (l *Limited) GetPer() LimitPer    { return l.Per }

// validate checks if l is valid. Limited is invalid if Per is invalid or if
// MaxRequests is zero or if Period is less than or equal to zero.
func (l *Limited) validate() error {
	switch {
	case !l.Per.IsValid():
		return ErrInvalidLimitPer
	case l.MaxRequests == 0:
		return fmt.Errorf("%w: max requests must be greater than zero", ErrInvalidLimit)
	case l.Period <= 0:
		return fmt.Errorf("%w: period must be greater than zero", ErrInvalidLimit)
	}

	return nil
}

// Unlimited is a Limit that allows an unlimited number of requests.
type Unlimited struct {
	Action   string
	Resource string
	Per      LimitPer
}

func (u *Unlimited) GetResource() string { return u.Resource }
func (u *Unlimited) GetAction() string   { return u.Action }
func (u *Unlimited) GetPer() LimitPer    { return u.Per }

// validate checks if u is valid. It is invalid if Per is invalid.
func (u *Unlimited) validate() error {
	switch {
	case !u.Per.IsValid():
		return ErrInvalidLimitPer
	}
	return nil
}
