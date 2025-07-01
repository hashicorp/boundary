// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
)

type testOptions struct {
	// test options
	withDescription string
}

func testDefaults() testOptions {
	return testOptions{}
}

func getTestOpts(opt ...Option) testOptions {
	opts := testDefaults()
	applyOpts(&opts, opt...)
	return opts
}

// WithDescription allows you to specify an optional description.
func WithDescription(desc string) Option {
	return func(o interface{}) {
		if o, ok := o.(*testOptions); ok {
			o.withDescription = desc
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	require := require.New(t)
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	require.NoError(err)

	l, err := net.ListenTCP("tcp", addr)
	require.NoError(err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func testStartTLSRequestPacket(t *testing.T, messageID int) *packet {
	t.Helper()
	envelope := testRequestEnvelope(t, int(messageID))

	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "Start TLS")
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.4.1.1466.20037", "TLS Extended Command"))
	envelope.AppendChild(request)

	return &packet{
		Packet: envelope,
	}
}

func testSearchRequestPacket(t *testing.T, s SearchMessage) *packet {
	t.Helper()
	require := require.New(t)
	envelope := testRequestEnvelope(t, int(s.GetID()))
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchRequest, nil, "Search Request")
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s.BaseDN, "Base DN"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(s.Scope), "Scope"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(s.DerefAliases), "Deref Aliases"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(s.SizeLimit), "Size Limit"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(s.TimeLimit), "Time Limit"))
	pkt.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, s.TypesOnly, "Types Only"))

	// compile and encode filter
	filterPacket, err := ldap.CompileFilter(s.Filter)
	require.NoError(err)
	pkt.AppendChild(filterPacket)

	attributesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, attribute := range s.Attributes {
		attributesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attribute, "Attribute"))
	}
	pkt.AppendChild(attributesPacket)

	envelope.AppendChild(pkt)
	if len(s.Controls) > 0 {
		envelope.AppendChild(encodeControls(s.Controls))
	}

	return &packet{
		Packet: envelope,
	}
}

func testSimpleBindRequestPacket(t *testing.T, m SimpleBindMessage) *packet {
	t.Helper()

	envelope := testRequestEnvelope(t, int(m.GetID()))
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(3), "Version"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, m.UserName, "User Name"))
	pkt.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, string(m.Password), "Password"))
	envelope.AppendChild(pkt)

	if len(m.Controls) > 0 {
		envelope.AppendChild(encodeControls(m.Controls))
	}

	return &packet{
		Packet: envelope,
	}
}

func testUnbindRequestPacket(t *testing.T, m UnbindMessage) *packet {
	t.Helper()

	envelope := testRequestEnvelope(t, int(m.GetID()))
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationUnbindRequest, nil, "Unbind Request")
	envelope.AppendChild(pkt)

	return &packet{
		Packet: envelope,
	}
}

func testModifyRequestPacket(t *testing.T, m ModifyMessage) *packet {
	t.Helper()
	envelope := testRequestEnvelope(t, int(m.GetID()))
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationModifyRequest, nil, "Modify Request")
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, m.DN, "DN"))
	changes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Changes")
	for _, change := range m.Changes {
		changes.AppendChild(change.encode())
	}
	pkt.AppendChild(changes)

	envelope.AppendChild(pkt)
	if len(m.Controls) > 0 {
		envelope.AppendChild(encodeControls(m.Controls))
	}
	return &packet{
		Packet: envelope,
	}
}

func testDeleteRequestPacket(t *testing.T, m DeleteMessage) *packet {
	t.Helper()
	envelope := testRequestEnvelope(t, int(m.GetID()))
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationDelRequest, nil, "Delete Request")
	pkt.Data.Write([]byte(m.DN))

	envelope.AppendChild(pkt)
	if len(m.Controls) > 0 {
		envelope.AppendChild(encodeControls(m.Controls))
	}
	return &packet{
		Packet: envelope,
	}
}

func testAddRequestPacket(t *testing.T, m AddMessage) *packet {
	t.Helper()
	envelope := testRequestEnvelope(t, int(m.GetID()))
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationAddRequest, nil, "Add Request")
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, m.DN, "DN"))
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, attr := range m.Attributes {
		attributes.AppendChild(attr.encode())
	}
	pkt.AppendChild(attributes)

	envelope.AppendChild(pkt)
	if len(m.Controls) > 0 {
		envelope.AppendChild(encodeControls(m.Controls))
	}
	return &packet{
		Packet: envelope,
	}
}

func testRequestEnvelope(t *testing.T, messageID int) *ber.Packet {
	t.Helper()
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(messageID), "MessageID"))
	return p
}

func testControlString(t *testing.T, controlType string, opt ...Option) *ControlString {
	t.Helper()
	require := require.New(t)
	c, err := NewControlString(controlType, opt...)
	require.NoError(err)
	return c
}

func testControlManageDsaIT(t *testing.T, opt ...Option) *ControlManageDsaIT {
	t.Helper()
	require := require.New(t)
	c, err := NewControlManageDsaIT(opt...)
	require.NoError(err)
	return c
}

func testControlMicrosoftNotification(t *testing.T, opt ...Option) *ControlMicrosoftNotification {
	t.Helper()
	require := require.New(t)
	c, err := NewControlMicrosoftNotification(opt...)
	require.NoError(err)
	return c
}

func testControlMicrosoftServerLinkTTL(t *testing.T, opt ...Option) *ControlMicrosoftServerLinkTTL {
	t.Helper()
	require := require.New(t)
	c, err := NewControlMicrosoftServerLinkTTL(opt...)
	require.NoError(err)
	return c
}

func testControlMicrosoftShowDeleted(t *testing.T, opt ...Option) *ControlMicrosoftShowDeleted {
	t.Helper()
	require := require.New(t)
	c, err := NewControlMicrosoftShowDeleted(opt...)
	require.NoError(err)
	return c
}

func testControlPaging(t *testing.T, pagingSize uint32, opt ...Option) *ControlPaging {
	t.Helper()
	require := require.New(t)
	c, err := NewControlPaging(uint32(pagingSize), opt...)
	require.NoError(err)
	return c
}

// TestWithDebug specifies that the test should be run under "debug" mode
func TestWithDebug(t *testing.T) bool {
	t.Helper()
	return strings.ToLower(os.Getenv("DEBUG")) == "true"
}

func TestEncodeString(t *testing.T, tag ber.Tag, s string, opt ...Option) string {
	t.Helper()
	opts := getTestOpts(opt...)
	pkt := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, tag, s, opts.withDescription)
	dec, err := ber.DecodePacketErr(pkt.Bytes())
	require.NoError(t, err)
	return string(dec.Bytes())
}

type safeBuf struct {
	t   *testing.T
	buf *strings.Builder
	mu  *sync.RWMutex
}

func testSafeBuf(t *testing.T) *safeBuf {
	t.Helper()
	return &safeBuf{
		t:   t,
		mu:  &sync.RWMutex{},
		buf: &strings.Builder{},
	}
}

func (w *safeBuf) Write(p []byte) (n int, err error) {
	w.t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *safeBuf) String() string {
	w.t.Helper()
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.buf.String()
}
