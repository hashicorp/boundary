// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/storage"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func assertContainer(ctx context.Context, t *testing.T, path, state string, typ string, fs *fstest.MemContainer, keys *kms.Keys) {
	t.Helper()

	td := filepath.Join("testdata", t.Name(), state, path)

	// meta
	wantMeta, err := os.ReadFile(filepath.Join(td, string(typ)+"-recording.meta"))
	require.NoError(t, err, "unable to find test data file")
	meta, ok := fs.Files[string(typ)+"-recording.meta"]
	require.True(t, ok, "container is missing meta file")
	wantChecksumsRegex, err := regexp.Compile(string(wantMeta))
	require.NoError(t, err)
	assert.True(t, wantChecksumsRegex.MatchString(meta.Buf.String()))

	// summary
	wantSummary, err := os.ReadFile(filepath.Join(td, string(typ)+"-recording-summary.json"))
	require.NoError(t, err, "unable to find test data file")
	summary, ok := fs.Files[string(typ)+"-recording-summary.json"]
	require.True(t, ok, "container is missing summary file")
	assert.Equal(t, string(wantSummary), summary.Buf.String())

	// SHA256SUM checksums
	wantChecksums, err := os.ReadFile(filepath.Join(td, "SHA256SUM"))
	require.NoError(t, err, "unable to find test data file")
	checksums, ok := fs.Files["SHA256SUM"]
	require.True(t, ok, "container is missing checksums file")
	checksumSlice := strings.Split(string(wantChecksums), "\n")
	var wChecksumsRegex []*regexp.Regexp
	for _, c := range checksumSlice {
		r, err := regexp.Compile(c)
		require.NoError(t, err)
		wChecksumsRegex = append(wChecksumsRegex, r)
	}
	for _, cr := range wChecksumsRegex {
		assert.True(t, cr.MatchString(checksums.Buf.String()), "got:\n%s\nmust match:\n%s", checksums.Buf.String(), cr.String())
	}

	// SHA256SUM.sig signature file
	sig, ok := fs.Files["SHA256SUM.sig"]
	require.True(t, ok, "container is missing sig file")
	switch state {
	case "closed":
		want, err := keys.SignWithPrivKey(ctx, checksums.Buf.Bytes())
		require.NoError(t, err)

		got := &wrapping.SigInfo{}
		err = proto.Unmarshal(sig.Buf.Bytes(), got)
		require.NoError(t, err)

		assert.Empty(t,
			cmp.Diff(
				want,
				got,
				cmpopts.IgnoreUnexported(wrapping.SigInfo{}, wrapping.KeyInfo{}),
			),
		)
	default:
		assert.Equal(t, "", sig.Buf.String())
	}

	// journal
	wantJournal, err := os.ReadFile(filepath.Join(td, ".journal"))
	require.NoError(t, err, "unable to find test data file")
	journal, ok := fs.Files[".journal"]
	require.True(t, ok, "container is missing journal file")
	journalSlice := strings.Split(string(wantJournal), "\n")
	var wJournalRegex []*regexp.Regexp
	for _, c := range journalSlice {
		r, err := regexp.Compile(c)
		require.NoError(t, err)
		wJournalRegex = append(wJournalRegex, r)
	}
	for _, cr := range wJournalRegex {
		assert.True(t, cr.MatchString(journal.Buf.String()), "got:\n%s\nmust match:\n%s", journal.Buf.String(), cr.String())
	}

	if typ == "session" {
		// BSR keys, if this is a session container
		bsrPub, ok := fs.Files["bsrKey.pub"]
		require.True(t, ok, "container is missing bsrPub file")
		assert.NotEmpty(t, bsrPub.Buf.String())

		wrappedBsrKey, ok := fs.Files["wrappedBsrKey"]
		require.True(t, ok, "container is missing wrappedBsrKey file")
		assert.NotEmpty(t, wrappedBsrKey.Buf.String())

		wrappedPrivKey, ok := fs.Files["wrappedPrivKey"]
		require.True(t, ok, "container is missing wrappedPrivKey file")
		assert.NotEmpty(t, wrappedPrivKey.Buf.String())

		pubKeyBsrSignature, ok := fs.Files["pubKeyBsrSignature.sign"]
		require.True(t, ok, "container is missing pubKeyBsrSignature.sign file")
		assert.NotEmpty(t, pubKeyBsrSignature.Buf.String())

		pubKeySelfSignature, ok := fs.Files["pubKeySelfSignature.sign"]
		require.True(t, ok, "container is missing pubKeySelfSignature.sign file")
		assert.NotEmpty(t, pubKeySelfSignature.Buf.String())

		sessionMeta, ok := fs.Files["session-meta.json"]
		require.True(t, ok, "container is missing session-meta.json file")
		assert.NotEmpty(t, sessionMeta.Buf.String())
		sm := &bsr.SessionMeta{}
		err = json.Unmarshal(sessionMeta.Buf.Bytes(), sm)
		require.NoError(t, err)
		assert.Equal(t, sm, bsr.TestSessionMeta(strings.ReplaceAll(fs.Name, ".bsr", "")))
	}
}

type connection struct {
	mem  *fstest.MemContainer
	conn *bsr.Connection
	id   string

	channels []*channel
	files    []*file
}

type channel struct {
	mem     *fstest.MemContainer
	channel *bsr.Channel
	id      string

	files []*file
}

type file struct {
	mem  *fstest.MemFile
	file io.Writer
}

type createConn struct {
	id       string
	channels []createChannel
	files    []createFile
}

type createChannel struct {
	id    string
	files []createFile
}

type createFile struct {
	typ string
	dir bsr.Direction
}

func TestBsr(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name  string
		id    string
		opts  []bsr.Option
		c     *fstest.MemFS
		keys  *kms.Keys
		conns []createConn
	}{
		{
			"session_not_multiplexed",
			"session_123456789",
			[]bsr.Option{},
			fstest.NewMemFS(),
			func() *kms.Keys {
				keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session_123456789")
				require.NoError(t, err)
				return keys
			}(),
			[]createConn{
				{
					"conn_1",
					nil,
					[]createFile{
						{"messages", bsr.Inbound},
						{"messages", bsr.Outbound},
						{"requests", bsr.Inbound},
						{"requests", bsr.Outbound},
					},
				},
			},
		},
		{
			"session_multiplexed",
			"session_123456789",
			[]bsr.Option{bsr.WithSupportsMultiplex(true)},
			fstest.NewMemFS(),
			func() *kms.Keys {
				keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session_123456789")
				require.NoError(t, err)
				return keys
			}(),
			[]createConn{
				{
					"conn_1",
					[]createChannel{
						{
							"chan_1",
							[]createFile{
								{"messages", bsr.Inbound},
								{"requests", bsr.Inbound},
								{"messages", bsr.Outbound},
								{"requests", bsr.Outbound},
							},
						},
					},
					[]createFile{
						{"requests", bsr.Inbound},
						{"requests", bsr.Outbound},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srm := &bsr.SessionRecordingMeta{
				Id:       tc.id,
				Protocol: bsr.Protocol("TEST"),
			}
			sessionMeta := bsr.TestSessionMeta(tc.id)
			s, err := bsr.NewSession(ctx, srm, sessionMeta, tc.c, tc.keys, tc.opts...)
			require.NoError(t, err)
			require.NotNil(t, s)

			sContainer, ok := tc.c.Containers[tc.id+".bsr"]
			require.True(t, ok)

			assertContainer(ctx, t, "", "opened", "session", sContainer, tc.keys)

			createdConnections := make([]*connection, 0)

			// create all the things
			for _, conn := range tc.conns {
				c, err := s.NewConnection(ctx, &bsr.ConnectionRecordingMeta{Id: conn.id})
				require.NoError(t, err)
				require.NotNil(t, c)

				cContainer, ok := sContainer.Sub[conn.id+".connection"]
				require.True(t, ok)

				assertContainer(ctx, t, conn.id, "opened", "connection", cContainer, tc.keys)

				ff := make([]*file, 0, len(conn.files))
				for _, f := range conn.files {
					var w io.Writer
					var err error
					switch f.typ {
					case "messages":
						w, err = c.NewMessagesWriter(ctx, f.dir)
					case "requests":
						w, err = c.NewRequestsWriter(ctx, f.dir)
					}
					require.NoError(t, err)

					fname := fmt.Sprintf("%s-%s.data", f.typ, f.dir.String())
					memf, ok := cContainer.Files[fname]
					require.True(t, ok, "file %s not in container %s", fname, cContainer.Name)

					require.NoError(t, err)
					ff = append(ff, &file{
						mem:  memf,
						file: w,
					})
				}

				createdChannels := make([]*channel, 0, len(conn.channels))
				for _, chann := range conn.channels {
					ch, err := c.NewChannel(ctx, &bsr.ChannelRecordingMeta{Id: chann.id, Type: "chan"})
					require.NoError(t, err)
					require.NotNil(t, ch)

					chContainer, ok := cContainer.Sub[chann.id+".channel"]
					require.True(t, ok)

					assertContainer(ctx, t, filepath.Join(conn.id, chann.id), "opened", "channel", chContainer, tc.keys)

					ff := make([]*file, 0, len(chann.files))
					for _, f := range chann.files {
						var w io.Writer
						var err error
						switch f.typ {
						case "messages":
							w, err = ch.NewMessagesWriter(ctx, f.dir)
						case "requests":
							w, err = ch.NewRequestsWriter(ctx, f.dir)
						}
						require.NoError(t, err)

						fname := fmt.Sprintf("%s-%s.data", f.typ, f.dir.String())
						memf, ok := chContainer.Files[fname]
						require.True(t, ok, "file %s not in container %s", fname, chContainer.Name)

						require.NoError(t, err)
						ff = append(ff, &file{
							mem:  memf,
							file: w,
						})
					}
					createdChannels = append(createdChannels, &channel{
						mem:     chContainer,
						channel: ch,
						id:      chann.id,
						files:   ff,
					})
				}
				createdConnections = append(createdConnections, &connection{
					mem:      cContainer,
					conn:     c,
					id:       conn.id,
					channels: createdChannels,
					files:    ff,
				})
			}

			// now close all the things that where created.
			for _, conn := range createdConnections {
				for _, channel := range conn.channels {
					for _, f := range channel.files {
						v, ok := f.file.(io.Closer)
						require.True(t, ok, "file is not a io.Closer")
						err = v.Close()
						require.NoError(t, err)
					}
					err = channel.channel.Close(ctx)
					require.NoError(t, err)

					assertContainer(ctx, t, filepath.Join(conn.id, channel.id), "closed", "channel", channel.mem, tc.keys)
				}

				for _, f := range conn.files {
					v, ok := f.file.(io.Closer)
					require.True(t, ok, "file is not a io.Closer")
					err = v.Close()
					require.NoError(t, err)
				}

				err = conn.conn.Close(ctx)
				require.NoError(t, err)
				assertContainer(ctx, t, conn.id, "closed", "connection", conn.mem, tc.keys)
			}

			err = s.Close(ctx)
			require.NoError(t, err)

			assertContainer(ctx, t, "", "closed", "session", sContainer, tc.keys)
		})
	}
}

func TestNewSessionErrors(t *testing.T) {
	ctx := context.Background()

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	cases := []struct {
		name        string
		meta        *bsr.SessionRecordingMeta
		sessionMeta *bsr.SessionMeta
		f           storage.FS
		keys        *kms.Keys
		wantError   error
	}{
		{
			"nil-meta",
			nil,
			bsr.TestSessionMeta("session"),
			&fstest.MemFS{},
			keys,
			errors.New("bsr.NewSession: missing meta: invalid parameter"),
		},
		{
			"nil-session-meta",
			bsr.TestSessionRecordingMeta("session_recording", bsr.Protocol("TEST")),
			nil,
			&fstest.MemFS{},
			keys,
			errors.New("bsr.NewSession: missing session meta: invalid parameter"),
		},
		{
			"empty-session-id",
			bsr.TestSessionRecordingMeta("", bsr.Protocol("TEST")),
			bsr.TestSessionMeta("session"),
			&fstest.MemFS{},
			keys,
			errors.New("bsr.NewSession: missing session id: invalid parameter"),
		},
		{
			"nil-fs",
			bsr.TestSessionRecordingMeta("session_recording", bsr.Protocol("TEST")),
			bsr.TestSessionMeta("session"),
			nil,
			keys,
			errors.New("bsr.NewSession: missing storage fs: invalid parameter"),
		},
		{
			"nil-keys",
			bsr.TestSessionRecordingMeta("session_recording", bsr.Protocol("TEST")),
			bsr.TestSessionMeta("session"),
			&fstest.MemFS{},
			nil,
			errors.New("bsr.NewSession: missing kms keys: invalid parameter"),
		},
		{
			"missing-bsr-signature",
			bsr.TestSessionRecordingMeta("session_recording", bsr.Protocol("TEST")),
			bsr.TestSessionMeta("session"),
			&fstest.MemFS{},
			&kms.Keys{
				PubKey:              keys.PubKey,
				WrappedBsrKey:       keys.WrappedBsrKey,
				WrappedPrivKey:      keys.WrappedPrivKey,
				PubKeySelfSignature: keys.PubKeySelfSignature,
			},
			errors.New("bsr.persistBsrSessionKeys: missing kms pub key BSR signature: invalid parameter\nbsr.NewSession: could not persist BSR keys"),
		},
		{
			"missing-pub-signature",
			bsr.TestSessionRecordingMeta("session_recording", bsr.Protocol("TEST")),
			bsr.TestSessionMeta("session"),
			&fstest.MemFS{},
			&kms.Keys{
				PubKey:             keys.PubKey,
				WrappedBsrKey:      keys.WrappedBsrKey,
				WrappedPrivKey:     keys.WrappedPrivKey,
				PubKeyBsrSignature: keys.PubKeyBsrSignature,
			},
			errors.New("bsr.persistBsrSessionKeys: missing kms pub key self signature: invalid parameter\nbsr.NewSession: could not persist BSR keys"),
		},
		{
			"missing-pub-key",
			bsr.TestSessionRecordingMeta("session_recording", bsr.Protocol("TEST")),
			bsr.TestSessionMeta("session"),
			&fstest.MemFS{},
			&kms.Keys{
				WrappedBsrKey:       keys.WrappedBsrKey,
				WrappedPrivKey:      keys.WrappedPrivKey,
				PubKeySelfSignature: keys.PubKeySelfSignature,
				PubKeyBsrSignature:  keys.PubKeyBsrSignature,
			},
			errors.New("bsr.persistBsrSessionKeys: missing kms pub key: invalid parameter\nbsr.NewSession: could not persist BSR keys"),
		},
		{
			"missing-wrapped-bsr-key",
			bsr.TestSessionRecordingMeta("session_recording", bsr.Protocol("TEST")),
			bsr.TestSessionMeta("session"),
			&fstest.MemFS{},
			&kms.Keys{
				PubKey:              keys.PubKey,
				WrappedPrivKey:      keys.WrappedPrivKey,
				PubKeySelfSignature: keys.PubKeySelfSignature,
				PubKeyBsrSignature:  keys.PubKeyBsrSignature,
			},
			errors.New("bsr.persistBsrSessionKeys: missing kms wrapped BSR key: invalid parameter\nbsr.NewSession: could not persist BSR keys"),
		},
		{
			"missing-wrapped-priv-key",
			bsr.TestSessionRecordingMeta("session_recording", bsr.Protocol("TEST")),
			bsr.TestSessionMeta("session"),
			&fstest.MemFS{},
			&kms.Keys{
				PubKey:              keys.PubKey,
				WrappedBsrKey:       keys.WrappedBsrKey,
				PubKeySelfSignature: keys.PubKeySelfSignature,
				PubKeyBsrSignature:  keys.PubKeyBsrSignature,
			},
			errors.New("bsr.persistBsrSessionKeys: missing kms wrapped priv key: invalid parameter\nbsr.NewSession: could not persist BSR keys"),
		},
		{
			"fs-new-error",
			bsr.TestSessionRecordingMeta("session_recording", bsr.Protocol("TEST")),
			bsr.TestSessionMeta("session"),
			fstest.NewMemFS(fstest.WithNewFunc(func(_ context.Context, _ string) (storage.Container, error) {
				return nil, errors.New("fs new error")
			})),
			keys,
			errors.New("fs new error"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bsr.NewSession(ctx, tc.meta, tc.sessionMeta, tc.f, tc.keys)
			require.Error(t, err)
			assert.EqualError(t, err, tc.wantError.Error())
		})
	}
}

func TestNewConnectionErrors(t *testing.T) {
	ctx := context.Background()

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	cases := []struct {
		name      string
		session   *bsr.Session
		meta      *bsr.ConnectionRecordingMeta
		wantError error
	}{
		{
			"nil-meta",
			func() *bsr.Session {
				s, err := bsr.NewSession(ctx, bsr.TestSessionRecordingMeta("session_recording", bsr.Protocol("TEST")), bsr.TestSessionMeta("session"), &fstest.MemFS{}, keys)
				require.NoError(t, err)
				return s
			}(),
			nil,
			errors.New("bsr.(Session).NewConnection: missing connection meta: invalid parameter"),
		},
		{
			"empty-connection-id",
			func() *bsr.Session {
				s, err := bsr.NewSession(ctx, bsr.TestSessionRecordingMeta("session_recording", bsr.Protocol("TEST")), bsr.TestSessionMeta("session"), &fstest.MemFS{}, keys)
				require.NoError(t, err)
				return s
			}(),
			&bsr.ConnectionRecordingMeta{Id: ""},
			errors.New("bsr.(Session).NewConnection: missing connection id: invalid parameter"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.session.NewConnection(ctx, tc.meta)
			require.Error(t, err)
			assert.EqualError(t, err, tc.wantError.Error())
		})
	}
}

func TestNewChannelErrors(t *testing.T) {
	ctx := context.Background()

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	srm := bsr.TestSessionRecordingMeta("session_recording", bsr.Protocol("TEST"))
	sessionMeta := bsr.TestSessionMeta("session")
	cases := []struct {
		name       string
		connection *bsr.Connection
		meta       *bsr.ChannelRecordingMeta
		wantError  error
	}{
		{
			"nil-meta",
			func() *bsr.Connection {
				s, err := bsr.NewSession(ctx, srm, sessionMeta, &fstest.MemFS{}, keys, bsr.WithSupportsMultiplex(true))
				require.NoError(t, err)

				c, err := s.NewConnection(ctx, &bsr.ConnectionRecordingMeta{Id: "connection"})
				require.NoError(t, err)
				return c
			}(),
			nil,
			errors.New("bsr.(Connection).NewChannel: missing channel meta: invalid parameter"),
		},
		{
			"empty-connection-id",
			func() *bsr.Connection {
				s, err := bsr.NewSession(ctx, srm, sessionMeta, &fstest.MemFS{}, keys, bsr.WithSupportsMultiplex(true))
				require.NoError(t, err)

				c, err := s.NewConnection(ctx, &bsr.ConnectionRecordingMeta{Id: "connection"})
				require.NoError(t, err)
				return c
			}(),
			&bsr.ChannelRecordingMeta{Id: ""},
			errors.New("bsr.(Connection).NewChannel: missing channel id: invalid parameter"),
		},
		{
			"not-multiplexed",
			func() *bsr.Connection {
				s, err := bsr.NewSession(ctx, srm, sessionMeta, &fstest.MemFS{}, keys, bsr.WithSupportsMultiplex(false))
				require.NoError(t, err)

				c, err := s.NewConnection(ctx, &bsr.ConnectionRecordingMeta{Id: "connection"})
				require.NoError(t, err)
				return c
			}(),
			&bsr.ChannelRecordingMeta{Id: ""},
			errors.New("bsr.(Connection).NewChannel: connection cannot make channels: not supported by protocol"),
		},
		{
			"not-multiplexed-default",
			func() *bsr.Connection {
				s, err := bsr.NewSession(ctx, srm, sessionMeta, &fstest.MemFS{}, keys)
				require.NoError(t, err)

				c, err := s.NewConnection(ctx, &bsr.ConnectionRecordingMeta{Id: "connection"})
				require.NoError(t, err)
				return c
			}(),
			&bsr.ChannelRecordingMeta{Id: ""},
			errors.New("bsr.(Connection).NewChannel: connection cannot make channels: not supported by protocol"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.connection.NewChannel(ctx, tc.meta)
			require.Error(t, err)
			assert.EqualError(t, err, tc.wantError.Error())
		})
	}
}

func TestChannelNewMessagesWriterErrors(t *testing.T) {
	ctx := context.Background()

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	srm := bsr.TestSessionRecordingMeta("session_recording", bsr.Protocol("TEST"))
	sessionMeta := bsr.TestSessionMeta("session")
	cases := []struct {
		name      string
		channel   *bsr.Channel
		dir       bsr.Direction
		wantError error
	}{
		{
			"invalid-dir",
			func() *bsr.Channel {
				s, err := bsr.NewSession(ctx, srm, sessionMeta, &fstest.MemFS{}, keys, bsr.WithSupportsMultiplex(true))
				require.NoError(t, err)

				c, err := s.NewConnection(ctx, &bsr.ConnectionRecordingMeta{Id: "connection"})
				require.NoError(t, err)

				ch, err := c.NewChannel(ctx, &bsr.ChannelRecordingMeta{Id: "channel"})
				require.NoError(t, err)
				return ch
			}(),
			bsr.Direction(uint8(255)),
			errors.New("bsr.(Channel).NewMessagesWriter: invalid direction: invalid parameter"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.channel.NewMessagesWriter(ctx, tc.dir)
			require.Error(t, err)
			assert.EqualError(t, err, tc.wantError.Error())
		})
	}
}

func TestChannelNewRequestsWriterErrors(t *testing.T) {
	ctx := context.Background()

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	srm := bsr.TestSessionRecordingMeta("session_recording", bsr.Protocol("TEST"))
	sessionMeta := bsr.TestSessionMeta("session")
	cases := []struct {
		name      string
		channel   *bsr.Channel
		dir       bsr.Direction
		wantError error
	}{
		{
			"invalid-dir",
			func() *bsr.Channel {
				s, err := bsr.NewSession(ctx, srm, sessionMeta, &fstest.MemFS{}, keys, bsr.WithSupportsMultiplex(true))
				require.NoError(t, err)

				c, err := s.NewConnection(ctx, &bsr.ConnectionRecordingMeta{Id: "connection"})
				require.NoError(t, err)

				ch, err := c.NewChannel(ctx, &bsr.ChannelRecordingMeta{Id: "channel"})
				require.NoError(t, err)
				return ch
			}(),
			bsr.Direction(uint8(255)),
			errors.New("bsr.(Channel).NewRequestsWriter: invalid direction: invalid parameter"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.channel.NewRequestsWriter(ctx, tc.dir)
			require.Error(t, err)
			assert.EqualError(t, err, tc.wantError.Error())
		})
	}
}
