// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"bufio"
	"fmt"
	"sync"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/hashicorp/go-hclog"
)

// ResponseWriter is an ldap request response writer which is used by a
// HanderFunc to write responses to client requests.
type ResponseWriter struct {
	writerMu  *sync.Mutex // a shared lock across all requests to prevent data races when writing
	writer    *bufio.Writer
	logger    hclog.Logger
	connID    int
	requestID int
}

func newResponseWriter(w *bufio.Writer, lock *sync.Mutex, logger hclog.Logger, connID, requestID int) (*ResponseWriter, error) {
	const op = "gldap.NewResponseWriter"
	if w == nil {
		return nil, fmt.Errorf("%s: missing writer: %w", op, ErrInvalidParameter)
	}
	if lock == nil {
		return nil, fmt.Errorf("%s: missing writer lock: %w", op, ErrInvalidParameter)
	}
	if logger == nil {
		return nil, fmt.Errorf("%s: missing logger: %w", op, ErrInvalidParameter)
	}
	if connID == 0 {
		return nil, fmt.Errorf("%s: missing conn ID: %w", op, ErrInvalidParameter)
	}
	if requestID == 0 {
		return nil, fmt.Errorf("%s: missing request ID: %w", op, ErrInvalidParameter)
	}
	return &ResponseWriter{
		writerMu:  lock,
		writer:    w,
		logger:    logger,
		connID:    connID,
		requestID: requestID,
	}, nil
}

// Write will write the response to the client
func (rw *ResponseWriter) Write(r Response) error {
	const op = "gldap.(ResponseWriter).Write"
	if r == nil {
		return fmt.Errorf("%s: missing response: %w", op, ErrInvalidParameter)
	}
	p := r.packet()
	if rw.logger.IsDebug() {
		rw.logger.Debug("response write", "op", op, "conn", rw.connID, "requestID", rw.requestID)
		p.Log(rw.logger.StandardWriter(&hclog.StandardLoggerOptions{}), 0, false)
	}
	rw.writerMu.Lock()
	defer rw.writerMu.Unlock()
	if _, err := rw.writer.Write(r.packet().Bytes()); err != nil {
		return fmt.Errorf("%s: unable to write response: %w", op, err)
	}
	if err := rw.writer.Flush(); err != nil {
		return fmt.Errorf("%s: unable to flush write: %w", op, err)
	}
	rw.logger.Debug("finished writing", "op", op, "conn", rw.connID, "requestID", rw.requestID)
	return nil
}

func beginResponse(messageID int64) *ber.Packet {
	const op = "gldap.beginResponse" // nolint:unused
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	return p
}

func addOptionalResponseChildren(bindResponse *ber.Packet, opt ...Option) {
	const op = "gldap.addOptionalResponseChildren" // nolint:unused
	opts := getResponseOpts(opt...)
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, opts.withMatchedDN, "matchedDN"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, opts.withDiagnosticMessage, "diagnosticMessage"))
}

// Response represents a response to an ldap request
type Response interface {
	packet() *packet
}

type baseResponse struct {
	messageID   int64
	code        int16
	diagMessage string
	matchedDN   string
}

// SetResultCode the result code for a response.
func (l *baseResponse) SetResultCode(code int) {
	l.code = int16(code)
}

// SetDiagnosticMessage sets the optional diagnostic message for a response.
func (l *baseResponse) SetDiagnosticMessage(msg string) {
	l.diagMessage = msg
}

// SetMatchedDN sets the optional matched DN for a response.
func (l *baseResponse) SetMatchedDN(dn string) {
	l.matchedDN = dn
}

// ExtendedResponse represents a response to an extended operation request
type ExtendedResponse struct {
	*baseResponse
	name ExtendedOperationName
}

// SetResponseName will set the response name for the extended operation response.
func (r *ExtendedResponse) SetResponseName(n ExtendedOperationName) {
	r.name = n
}

func (r *ExtendedResponse) packet() *packet {
	replyPacket := beginResponse(r.messageID)

	// a new packet for the bind response
	resultPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ApplicationExtendedResponse), nil, ApplicationCodeMap[ApplicationExtendedResponse])
	// append the result code to the bind response packet
	resultPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, r.code, ResultCodeMap[uint16(r.code)]))

	// Add optional diagnostic message and matched DN
	addOptionalResponseChildren(resultPacket, WithDiagnosticMessage(r.diagMessage), WithMatchedDN(r.matchedDN))

	replyPacket.AppendChild(resultPacket)
	return &packet{Packet: replyPacket}
}

// BindResponse represents the response to a bind request
type BindResponse struct {
	*baseResponse
	controls []Control
}

// SetControls for bind response
func (r *BindResponse) SetControls(controls ...Control) {
	r.controls = controls
}

func (r *BindResponse) packet() *packet {
	replyPacket := beginResponse(r.messageID)

	// a new packet for the bind response
	resultPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ApplicationBindResponse), nil, ApplicationCodeMap[ApplicationBindResponse])
	// append the result code to the bind response packet
	resultPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, r.code, ResultCodeMap[uint16(r.code)]))

	// Add optional diagnostic message and matched DN
	addOptionalResponseChildren(resultPacket, WithDiagnosticMessage(r.diagMessage), WithMatchedDN(r.matchedDN))

	replyPacket.AppendChild(resultPacket)
	if len(r.controls) > 0 {
		replyPacket.AppendChild(encodeControls(r.controls))
	}

	return &packet{Packet: replyPacket}
}

// GeneralResponse represents a general response (non-specific to a request).
type GeneralResponse struct {
	*baseResponse
	applicationCode int
}

func (r *GeneralResponse) packet() *packet {
	const op = "gldap.(GeneralResponse).packet" // nolint:unused
	replyPacket := beginResponse(r.messageID)

	// a new packet for the bind response
	resultPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(r.applicationCode), nil, ApplicationCodeMap[uint8(r.applicationCode)])
	// append the result code to the bind response packet
	resultPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, r.code, ResultCodeMap[uint16(r.code)]))

	// Add optional diagnostic message and matched DN
	addOptionalResponseChildren(resultPacket, WithDiagnosticMessage(r.diagMessage), WithMatchedDN(r.matchedDN))

	replyPacket.AppendChild(resultPacket)
	return &packet{Packet: replyPacket}
}

// SearchResponseDone represents that handling a search requests is done.
type SearchResponseDone struct {
	*baseResponse
	controls []Control
}

// SetControls for the search response
func (r *SearchResponseDone) SetControls(controls ...Control) {
	r.controls = controls
}

func (r *SearchResponseDone) packet() *packet {
	const op = "gldap.(SearchDoneResponse).packet" // nolint:unused
	replyPacket := beginResponse(r.messageID)

	resultPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultDone, nil, ApplicationCodeMap[ApplicationSearchResultDone])
	resultPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, r.code, ResultCodeMap[uint16(r.code)]))

	// Add optional diagnostic message and matched DN
	addOptionalResponseChildren(resultPacket, WithDiagnosticMessage(r.diagMessage), WithMatchedDN(r.matchedDN))

	replyPacket.AppendChild(resultPacket)
	if len(r.controls) > 0 {
		replyPacket.AppendChild(encodeControls(r.controls))
	}
	return &packet{Packet: replyPacket}
}

// SearchResponseEntry is an ldap entry that's part of search response.
type SearchResponseEntry struct {
	*baseResponse
	entry Entry
}

// AddAttribute will an attributes to the response entry
func (r *SearchResponseEntry) AddAttribute(name string, values []string) {
	r.entry.Attributes = append(r.entry.Attributes, NewEntryAttribute(name, values))
}

func (r *SearchResponseEntry) packet() *packet {
	const op = "gldap.(SearchEntryResponse).packet" // nolint:unused
	replyPacket := beginResponse(r.messageID)

	resultPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, ApplicationCodeMap[ApplicationSearchResultEntry])
	resultPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, r.entry.DN, "DN"))
	attributesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, a := range r.entry.Attributes {
		attributesPacket.AppendChild(a.encode())
	}
	resultPacket.AppendChild(attributesPacket)

	replyPacket.AppendChild(resultPacket)
	return &packet{Packet: replyPacket}
}

// ModifyResponse is a response to a modify request.
type ModifyResponse struct {
	*GeneralResponse
}
