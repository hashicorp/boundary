// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"fmt"
)

// Scope represents the scope of a search (see: https://ldap.com/the-ldap-search-operation/)
type Scope int64

const (
	// BaseObject (often referred to as “base”): Indicates that only the entry
	// specified as the search base should be considered. None of its
	// subordinates will be considered.
	BaseObject Scope = 0

	// SingleLevel (often referred to as “one”): Indicates that only the
	// immediate children of the entry specified as the search base should be
	// considered. The base entry itself should not be considered, nor any
	// descendants of the immediate children of the base entry.
	SingleLevel Scope = 1

	// WholeSubtree (often referred to as “sub”): Indicates that the entry
	// specified as the search base, and all of its subordinates to any depth,
	// should be considered. Note that in the special case that the search base
	// DN is the null DN, the root DSE should not be considered in a
	// wholeSubtree search.
	WholeSubtree Scope = 2
)

// AuthChoice defines the authentication choice for bind message
type AuthChoice string

// SimpleAuthChoice specifies a simple user/password authentication choice for
// the bind message
const SimpleAuthChoice AuthChoice = "simple"

type requestType string

const (
	unknownRequestType  requestType = ""
	bindRequestType     requestType = "bind"
	searchRequestType   requestType = "search"
	extendedRequestType requestType = "extended"
	modifyRequestType   requestType = "modify"
	addRequestType      requestType = "add"
	deleteRequestType   requestType = "delete"
	unbindRequestType   requestType = "unbind"
)

// Message defines a common interface for all messages
type Message interface {
	// GetID returns the message ID
	GetID() int64
}

// baseMessage defines a common base type for all messages (typically embedded)
type baseMessage struct {
	id int64
}

// GetID() returns the message ID
func (m baseMessage) GetID() int64 { return m.id }

// SearchMessage is a search request message
type SearchMessage struct {
	baseMessage
	// BaseDN for the request
	BaseDN string
	// Scope of the request
	Scope Scope
	// DerefAliases for the request
	DerefAliases int
	// TimeLimit is the max time in seconds to spend processing
	TimeLimit int64
	// SizeLimit is the max number of results to return
	SizeLimit int64
	// TypesOnly is true if the client only expects type info
	TypesOnly bool
	// Filter for the request
	Filter string
	// Attributes requested
	Attributes []string
	// Controls requested
	Controls []Control
}

// SimpleBindMessage is a simple bind request message
type SimpleBindMessage struct {
	baseMessage
	// AuthChoice for the request (SimpleAuthChoice)
	AuthChoice AuthChoice
	// UserName for the bind request
	UserName string
	// Password for the bind request
	Password Password
	// Controls are optional controls for the bind request
	Controls []Control
}

// ExtendedOperationMessage is an extended operation request message
type ExtendedOperationMessage struct {
	baseMessage
	// Name of the extended operation
	Name ExtendedOperationName
	// Value of the extended operation
	Value string
}

// DeleteMessage is an delete request message
type DeleteMessage struct {
	baseMessage
	// DN identifies the entry being added
	DN string

	// Controls hold optional controls to send with the request
	Controls []Control
}

// UnbindMessage is an unbind request message
type UnbindMessage struct {
	baseMessage
}

// newMessage will create a new message from the packet.
func newMessage(p *packet) (Message, error) {
	const op = "gldap.NewMessage"

	reqType, err := p.requestType()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	msgID, err := p.requestMessageID()
	if err != nil {
		return nil, fmt.Errorf("%s: unable to get message id: %w", op, err)
	}

	switch reqType {
	case unbindRequestType:
		return &UnbindMessage{
			baseMessage: baseMessage{
				id: msgID,
			},
		}, nil
	case bindRequestType:
		u, pass, controls, err := p.simpleBindParameters()
		if err != nil {
			return nil, fmt.Errorf("%s: invalid bind message: %w", op, err)
		}
		return &SimpleBindMessage{
			baseMessage: baseMessage{
				id: msgID,
			},
			UserName:   u,
			Password:   pass,
			AuthChoice: SimpleAuthChoice,
			Controls:   controls,
		}, nil
	case searchRequestType:
		parameters, err := p.searchParmeters()
		if err != nil {
			return nil, fmt.Errorf("%s: invalid search message: %w", op, err)
		}
		return &SearchMessage{
			baseMessage: baseMessage{
				id: msgID,
			},
			BaseDN:       parameters.baseDN,
			Scope:        Scope(parameters.scope),
			DerefAliases: int(parameters.derefAliases),
			SizeLimit:    parameters.sizeLimit,
			TimeLimit:    parameters.timeLimit,
			TypesOnly:    parameters.typesOnly,
			Filter:       parameters.filter,
			Attributes:   parameters.attributes,
			Controls:     parameters.controls,
		}, nil
	case extendedRequestType:
		opName, err := p.extendedOperationName()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &ExtendedOperationMessage{
			baseMessage: baseMessage{
				id: msgID,
			},
			Name: opName,
		}, nil
	case modifyRequestType:
		parameters, err := p.modifyParameters()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &ModifyMessage{
			baseMessage: baseMessage{
				id: msgID,
			},
			DN:       parameters.dn,
			Changes:  parameters.changes,
			Controls: parameters.controls,
		}, nil
	case addRequestType:
		parameters, err := p.addParameters()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &AddMessage{
			baseMessage: baseMessage{
				id: msgID,
			},
			DN:         parameters.dn,
			Attributes: parameters.attributes,
			Controls:   parameters.controls,
		}, nil
	case deleteRequestType:
		dn, controls, err := p.deleteParameters()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &DeleteMessage{
			baseMessage: baseMessage{
				id: msgID,
			},
			DN:       dn,
			Controls: controls,
		}, nil
	default:
		return &ExtendedOperationMessage{
			baseMessage: baseMessage{
				id: msgID,
			},
			Name: ExtendedOperationUnknown,
		}, nil
	}
}
