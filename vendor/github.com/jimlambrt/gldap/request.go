// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"crypto/tls"
	"errors"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// ExtendedOperationName is an extended operation request/response name
type ExtendedOperationName string

// Extended operation response/request names
const (
	ExtendedOperationDisconnection   ExtendedOperationName = "1.3.6.1.4.1.1466.2003"
	ExtendedOperationCancel          ExtendedOperationName = "1.3.6.1.1.8"
	ExtendedOperationStartTLS        ExtendedOperationName = "1.3.6.1.4.1.1466.20037"
	ExtendedOperationWhoAmI          ExtendedOperationName = "1.3.6.1.4.1.4203.1.11.3"
	ExtendedOperationGetConnectionID ExtendedOperationName = "1.3.6.1.4.1.26027.1.6.2"
	ExtendedOperationPasswordModify  ExtendedOperationName = "1.3.6.1.4.1.4203.1.11.1"
	ExtendedOperationUnknown         ExtendedOperationName = "Unknown"
)

// Request represents an ldap request
type Request struct {
	// ID is the request number for a specific connection.  Every connection has
	// its own request counter which starts at 1.
	ID int

	// conn is needed this for cancellation among other things.
	conn         *conn
	message      Message
	routeOp      routeOperation
	extendedName ExtendedOperationName
}

func newRequest(id int, c *conn, p *packet) (*Request, error) {
	const op = "gldap.newRequest"
	if c == nil {
		return nil, fmt.Errorf("%s: missing connection: %w", op, ErrInvalidParameter)
	}
	if p == nil {
		return nil, fmt.Errorf("%s: missing packet: %w", op, ErrInvalidParameter)
	}

	m, err := newMessage(p)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to build message for request %d: %w", op, id, err)
	}
	var extendedName ExtendedOperationName
	var routeOp routeOperation
	switch v := m.(type) {
	case *SimpleBindMessage:
		routeOp = bindRouteOperation
	case *SearchMessage:
		routeOp = searchRouteOperation
	case *ExtendedOperationMessage:
		routeOp = extendedRouteOperation
		extendedName = v.Name
	case *ModifyMessage:
		routeOp = modifyRouteOperation
	case *AddMessage:
		routeOp = addRouteOperation
	case *DeleteMessage:
		routeOp = deleteRouteOperation
	case *UnbindMessage:
		routeOp = unbindRouteOperation
	default:
		// this should be unreachable, since newMessage defaults to returning an
		// *ExtendedOperationMessage
		return nil, fmt.Errorf("%s: %v is an unsupported route operation: %w", op, v, ErrInternal)
	}

	r := &Request{
		ID:           id,
		conn:         c,
		message:      m,
		routeOp:      routeOp,
		extendedName: extendedName,
	}
	return r, nil
}

// ConnectionID returns the request's connection ID which enables you to know
// "who" (i.e. which connection) made a request. Using the connection ID you
// can do things like ensure a connection performing a search operation has
// successfully authenticated (a.k.a. performed a successful bind operation).
func (r *Request) ConnectionID() int {
	return r.conn.connID
}

// NewModifyResponse creates a modify response
// Supported options: WithResponseCode, WithDiagnosticMessage, WithMatchedDN
func (r *Request) NewModifyResponse(opt ...Option) *ModifyResponse {
	opts := getResponseOpts(opt...)
	return &ModifyResponse{
		GeneralResponse: r.NewResponse(
			WithApplicationCode(ApplicationModifyResponse),
			WithResponseCode(*opts.withResponseCode),
			WithDiagnosticMessage(opts.withDiagnosticMessage),
			WithMatchedDN(opts.withMatchedDN),
		),
	}
}

// StartTLS will start a TLS connection using the Message's existing connection
func (r *Request) StartTLS(tlsconfig *tls.Config) error {
	const op = "gldap.(Message).StartTLS"
	if tlsconfig == nil {
		return fmt.Errorf("%s: missing tls configuration: %w", op, ErrInvalidParameter)
	}
	tlsConn := tls.Server(r.conn.netConn, tlsconfig)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("%s: handshake error: %w", op, err)
	}
	if err := r.conn.initConn(tlsConn); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// NewResponse creates a general response (not necessarily to any specific
// request because you can set WithApplicationCode).
// Supported options: WithResponseCode, WithApplicationCode,
// WithDiagnosticMessage, WithMatchedDN
func (r *Request) NewResponse(opt ...Option) *GeneralResponse {
	const op = "gldap.NewResponse" // nolint:unused
	opts := getResponseOpts(opt...)
	if opts.withResponseCode == nil {
		opts.withResponseCode = intPtr(ResultUnwillingToPerform)
	}
	if opts.withApplicationCode == nil {
		opts.withApplicationCode = intPtr(ApplicationExtendedResponse)
	}
	return &GeneralResponse{
		baseResponse: &baseResponse{
			messageID:   r.message.GetID(),
			code:        int16(*opts.withResponseCode),
			diagMessage: opts.withDiagnosticMessage,
			matchedDN:   opts.withMatchedDN,
		},
		applicationCode: *opts.withApplicationCode,
	}
}

// NewExtendedResponse creates a new extended response.
// Supported options: WithResponseCode
func (r *Request) NewExtendedResponse(opt ...Option) *ExtendedResponse {
	const op = "gldap.NewExtendedResponse" // nolint:unused
	opts := getResponseOpts(opt...)
	resp := &ExtendedResponse{
		baseResponse: &baseResponse{
			messageID: r.message.GetID(),
		},
	}
	if opts.withResponseCode != nil {
		resp.code = int16(*opts.withResponseCode)
	}
	return resp
}

// NewBindResponse creates a new bind response.
// Supported options: WithResponseCode
func (r *Request) NewBindResponse(opt ...Option) *BindResponse {
	const op = "gldap.NewBindResponse" // nolint:unused
	opts := getResponseOpts(opt...)
	resp := &BindResponse{
		baseResponse: &baseResponse{
			messageID: r.message.GetID(),
		},
	}
	if opts.withResponseCode != nil {
		resp.code = int16(*opts.withResponseCode)
	}
	return resp
}

// GetSimpleBindMessage retrieves the SimpleBindMessage from the request, which
// allows you handle the request based on the message attributes.
func (r *Request) GetSimpleBindMessage() (*SimpleBindMessage, error) {
	const op = "gldap.(Request).GetSimpleBindMessage"
	s, ok := r.message.(*SimpleBindMessage)
	if !ok {
		return nil, fmt.Errorf("%s: %T not a simple bind request: %w", op, r.message, ErrInvalidParameter)
	}
	return s, nil
}

// NewSearchDoneResponse creates a new search done response.  If there are no
// results found, then set the response code by adding the option
// WithResponseCode(ResultNoSuchObject)
//
// Supported options: WithResponseCode
func (r *Request) NewSearchDoneResponse(opt ...Option) *SearchResponseDone {
	const op = "gldap.(Request).NewSearchDoneResponse" // nolint:unused
	opts := getResponseOpts(opt...)
	resp := &SearchResponseDone{
		baseResponse: &baseResponse{
			messageID: r.message.GetID(),
		},
	}
	if opts.withResponseCode != nil {
		resp.code = int16(*opts.withResponseCode)
	}
	return resp
}

// GetSearchMessage retrieves the SearchMessage from the request, which
// allows you handle the request based on the message attributes.
func (r *Request) GetSearchMessage() (*SearchMessage, error) {
	const op = "gldap.(Request).GetSearchMessage"
	m, ok := r.message.(*SearchMessage)
	if !ok {
		return nil, fmt.Errorf("%s: %T not a search request: %w", op, r.message, ErrInvalidParameter)
	}
	return m, nil
}

// NewSearchResponseEntry is a search response entry.
// Supported options: WithAttributes
func (r *Request) NewSearchResponseEntry(entryDN string, opt ...Option) *SearchResponseEntry {
	opts := getResponseOpts(opt...)
	newAttrs := make([]*EntryAttribute, 0, len(opts.withAttributes))
	for name, values := range opts.withAttributes {
		newAttrs = append(newAttrs, NewEntryAttribute(name, values))
	}
	return &SearchResponseEntry{
		baseResponse: &baseResponse{
			messageID: r.message.GetID(),
		},
		entry: Entry{
			DN:         entryDN,
			Attributes: newAttrs,
		},
	}
}

// GetModifyMessage retrieves the ModifyMessage from the request, which
// allows you handle the request based on the message attributes.
func (r *Request) GetModifyMessage() (*ModifyMessage, error) {
	const op = "gldap.(Request).GetModifyMessage"
	m, ok := r.message.(*ModifyMessage)
	if !ok {
		return nil, fmt.Errorf("%s: %T not a modify request: %w", op, r.message, ErrInvalidParameter)
	}
	return m, nil
}

// GetAddMessage retrieves the AddMessage from the request, which
// allows you handle the request based on the message attributes.
func (r *Request) GetAddMessage() (*AddMessage, error) {
	const op = "gldap.(Request).GetAddMessage"
	m, ok := r.message.(*AddMessage)
	if !ok {
		return nil, fmt.Errorf("%s: %T not a add request: %w", op, r.message, ErrInvalidParameter)
	}
	return m, nil
}

// GetDeleteMessage retrieves the DeleteMessage from the request, which
// allows you handle the request based on the message attributes.
func (r *Request) GetDeleteMessage() (*DeleteMessage, error) {
	const op = "gldap.(Request).GetDeleteMessage"
	m, ok := r.message.(*DeleteMessage)
	if !ok {
		return nil, fmt.Errorf("%s: %T not a delete request: %w", op, r.message, ErrInvalidParameter)
	}
	return m, nil
}

// GetUnbindMessage retrieves the UnbindMessage from the request, which
// allows you handle the request based on the message attributes.
func (r *Request) GetUnbindMessage() (*UnbindMessage, error) {
	const op = "gldap.(Request).GetUnbindMessage"
	m, ok := r.message.(*UnbindMessage)
	if !ok {
		return nil, fmt.Errorf("%s: %T not an unbind request: %w", op, r.message, ErrInvalidParameter)
	}
	return m, nil
}

// ConvertString will convert an ASN1 BER Octet string into a "native" go
// string.  Support ber string encoding types: OctetString, GeneralString and
// all other types will return an error.
func ConvertString(octetString ...string) ([]string, error) {
	const (
		op             = "gldap.ConvertOctetString"
		berTagIdx      = 0
		startOfDataIdx = 1
	)

	converted := make([]string, 0, len(octetString))

	for _, s := range octetString {
		data := []byte(s)

		switch {
		case
			ber.Tag(data[berTagIdx]) == ber.TagOctetString,
			ber.Tag(data[berTagIdx]) == ber.TagGeneralString:
			_, strDataLen, err := readLength(data[startOfDataIdx:])
			if err != nil {
				return nil, err
			}
			converted = append(converted, string(data[(startOfDataIdx+strDataLen):]))

		default:
			return nil, fmt.Errorf("%s: unsupported ber encoding type %s: %w", op, string(data[berTagIdx]), ErrInvalidParameter)
		}
	}

	return converted, nil
}

// readLength(...)
// jimlambrt: 2/2023
// copied directly from github.com/go-asn1-ber/asn1-ber@v1.5.4/length.go
// it has an MIT license: https://github.com/go-asn1-ber/asn1-ber/blob/master/LICENSE
func readLength(bytes []byte) (length int, read int, err error) {
	// length byte
	b := bytes[0]
	read++

	switch {
	case b == 0xFF:
		// Invalid 0xFF (x.600, 8.1.3.5.c)
		return 0, read, errors.New("invalid length byte 0xff")

	case b == ber.LengthLongFormBitmask:
		// Indefinite form, we have to decode packets until we encounter an EOC packet (x.600, 8.1.3.6)
		length = ber.LengthIndefinite

	case b&ber.LengthLongFormBitmask == 0:
		// Short definite form, extract the length from the bottom 7 bits (x.600, 8.1.3.4)
		length = int(b) & ber.LengthValueBitmask

	case b&ber.LengthLongFormBitmask != 0:
		// Long definite form, extract the number of length bytes to follow from the bottom 7 bits (x.600, 8.1.3.5.b)
		lengthBytes := int(b) & ber.LengthValueBitmask
		// Protect against overflow
		// TODO: support big int length?
		if lengthBytes > 8 {
			return 0, read, errors.New("long-form length overflow")
		}

		// Accumulate into a 64-bit variable
		var length64 int64
		for i := 0; i < lengthBytes; i++ {
			b = bytes[read]
			read++

			// x.600, 8.1.3.5
			length64 <<= 8
			length64 |= int64(b)
		}

		// Cast to a platform-specific integer
		length = int(length64)
		// Ensure we didn't overflow
		if int64(length) != length64 {
			return 0, read, errors.New("long-form length overflow")
		}

	default:
		return 0, read, errors.New("invalid length byte")
	}

	return length, read, nil
}

func intPtr(i int) *int {
	return &i
}
