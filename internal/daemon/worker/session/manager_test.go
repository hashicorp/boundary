// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestManager_Get(t *testing.T) {
	mockSessionClient := pbs.NewMockSessionServiceClient()
	mockSessionClient.LookupSessionFn = func(context.Context, *pbs.LookupSessionRequest) (*pbs.LookupSessionResponse, error) {
		return &pbs.LookupSessionResponse{
			Authorization: &targets.SessionAuthorizationData{
				SessionId:   "foo",
				Certificate: createTestCert(t),
			},
			Version:    1,
			Expiration: timestamppb.New(time.Now().Add(time.Hour)),
			Status:     pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
		}, nil
	}
	manager, err := NewManager(mockSessionClient)
	require.NoError(t, err)
	_, err = manager.LoadLocalSession(context.Background(), "foo", "worker id")
	require.NoError(t, err)

	assert.NotNil(t, manager.Get("foo"))
	assert.Nil(t, manager.Get("unknown"))
}

func TestManager_DeleteLocalSession(t *testing.T) {
	mockSessionClient := pbs.NewMockSessionServiceClient()
	mockSessionClient.LookupSessionFn = func(_ context.Context, req *pbs.LookupSessionRequest) (*pbs.LookupSessionResponse, error) {
		return &pbs.LookupSessionResponse{
			Authorization: &targets.SessionAuthorizationData{
				SessionId:   req.GetSessionId(),
				Certificate: createTestCert(t),
			},
			Version:    1,
			Expiration: timestamppb.New(time.Now().Add(time.Hour)),
			Status:     pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
		}, nil
	}
	manager, err := NewManager(mockSessionClient)
	require.NoError(t, err)
	_, err = manager.LoadLocalSession(context.Background(), "foo", "worker id")
	require.NoError(t, err)

	require.NotNil(t, manager.Get("foo"))
	manager.DeleteLocalSession([]string{"foo"})
	assert.Nil(t, manager.Get("foo"))
	// A second call to DeleteLocalSession is ok.
	manager.DeleteLocalSession([]string{"foo"})
	assert.Nil(t, manager.Get("foo"))
}

func TestManager_RequestCloseConnections(t *testing.T) {
	ctx := context.Background()
	mockSessionClient := pbs.NewMockSessionServiceClient()

	manager, err := NewManager(mockSessionClient)
	require.NoError(t, err)
	assert.False(t, manager.RequestCloseConnections(ctx, nil))
	assert.False(t, manager.RequestCloseConnections(ctx, map[string]*ConnectionCloseData{}))

	mockSessionClient.LookupSessionFn = func(_ context.Context, req *pbs.LookupSessionRequest) (*pbs.LookupSessionResponse, error) {
		return &pbs.LookupSessionResponse{
			Authorization: &targets.SessionAuthorizationData{
				SessionId:   req.GetSessionId(),
				Certificate: createTestCert(t),
			},
			Version:    1,
			Expiration: timestamppb.New(time.Now().Add(time.Hour)),
			Status:     pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
		}, nil
	}
	session1, err := manager.LoadLocalSession(ctx, "sess1", "worker id")
	require.NoError(t, err)
	session2, err := manager.LoadLocalSession(ctx, "sess2", "worker id")
	require.NoError(t, err)
	session3, err := manager.LoadLocalSession(ctx, "sess3", "worker id")
	require.NoError(t, err)

	mockSessionClient.CloseConnectionFn = func(context.Context, *pbs.CloseConnectionRequest) (*pbs.CloseConnectionResponse, error) {
		return nil, errors.New("error")
	}
	assert.False(t, manager.RequestCloseConnections(ctx, map[string]*ConnectionCloseData{"connection id": {SessionId: session1.GetId()}}))
	mockSessionClient.CloseConnectionFn = func(_ context.Context, req *pbs.CloseConnectionRequest) (*pbs.CloseConnectionResponse, error) {
		var data []*pbs.CloseConnectionResponseData
		for _, r := range req.GetCloseRequestData() {
			data = append(data, &pbs.CloseConnectionResponseData{
				ConnectionId: r.GetConnectionId(),
				Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED,
			})
		}
		return &pbs.CloseConnectionResponse{CloseResponseData: data}, nil
	}
	// There is no connection information yet for this connection.
	assert.False(t, manager.RequestCloseConnections(ctx, map[string]*ConnectionCloseData{
		"random_connection_id": {SessionId: session1.GetId()},
	}))

	// Load the connection info into the local storage
	mockSessionClient.AuthorizeConnectionFn = func(_ context.Context, req *pbs.AuthorizeConnectionRequest) (*pbs.AuthorizeConnectionResponse, error) {
		return &pbs.AuthorizeConnectionResponse{
			ConnectionId:    fmt.Sprintf("connection_%s", req.GetSessionId()),
			Status:          pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED,
			ConnectionsLeft: -1,
		}, nil
	}
	_, cancelFn := context.WithCancel(ctx)
	c1, _, err := session1.RequestAuthorizeConnection(ctx, "worker id", cancelFn)
	require.NoError(t, err)

	assert.True(t, manager.RequestCloseConnections(ctx, map[string]*ConnectionCloseData{
		c1.GetConnectionId(): {SessionId: session1.GetId()},
	}))

	c2, _, err := session2.RequestAuthorizeConnection(ctx, "worker id", cancelFn)
	require.NoError(t, err)
	c3, _, err := session3.RequestAuthorizeConnection(ctx, "worker id", cancelFn)
	require.NoError(t, err)
	assert.True(t, manager.RequestCloseConnections(ctx, map[string]*ConnectionCloseData{
		c2.GetConnectionId(): {SessionId: session2.GetId()},
		c3.GetConnectionId(): {SessionId: session3.GetId()},
	}))
}

func TestManager_LoadLocalSession(t *testing.T) {
	mockSessionClient := pbs.NewMockSessionServiceClient()
	errorCases := []struct {
		name               string
		inId               string
		inWorkerId         string
		controllerResponse func() (*pbs.LookupSessionResponse, error)
		wantError          string
	}{
		{
			name:       "no id",
			inWorkerId: "worker id",
			wantError:  "id is not set",
		},
		{
			name:      "no worker id",
			inId:      "id",
			wantError: "workerId is not set",
		},
		{
			name:       "controller error",
			inId:       "id",
			inWorkerId: "worker id",
			controllerResponse: func() (*pbs.LookupSessionResponse, error) {
				return nil, errors.New("some error")
			},
			wantError: "some error",
		},
		{
			name:       "cant parse cert",
			inId:       "id",
			inWorkerId: "worker id",
			controllerResponse: func() (*pbs.LookupSessionResponse, error) {
				return &pbs.LookupSessionResponse{
					Authorization: &targets.SessionAuthorizationData{
						SessionId:   "foo",
						Certificate: []byte("unparseable"),
					},
					Version:    1,
					Expiration: timestamppb.New(time.Now().Add(time.Hour)),
					Status:     pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
				}, nil
			},
			wantError: "error parsing session certificate",
		},
		{
			name:       "expired session",
			inId:       "id",
			inWorkerId: "worker id",
			controllerResponse: func() (*pbs.LookupSessionResponse, error) {
				return &pbs.LookupSessionResponse{
					Authorization: &targets.SessionAuthorizationData{
						SessionId:   "foo",
						Certificate: createTestCert(t),
					},
					Version:    1,
					Expiration: timestamppb.New(time.Now().Add(-time.Hour)),
					Status:     pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
				}, nil
			},
			wantError: "session is expired",
		},
	}
	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			mockSessionClient.LookupSessionFn = func(context.Context, *pbs.LookupSessionRequest) (*pbs.LookupSessionResponse, error) {
				return tc.controllerResponse()
			}
			manager, err := NewManager(mockSessionClient)
			require.NoError(t, err)
			s, err := manager.LoadLocalSession(context.Background(), tc.inId, tc.inWorkerId)
			require.Error(t, err)
			assert.Nil(t, s)

			assert.ErrorContains(t, err, tc.wantError)
		})
	}

	t.Run("success", func(t *testing.T) {
		expirationTime := time.Now().Add(time.Hour).UTC()
		mockSessionClient.LookupSessionFn = func(context.Context, *pbs.LookupSessionRequest) (*pbs.LookupSessionResponse, error) {
			return &pbs.LookupSessionResponse{
				Authorization: &targets.SessionAuthorizationData{
					SessionId:   "foo",
					Certificate: createTestCert(t),
				},
				ConnectionLimit: -1,
				Version:         1,
				Expiration:      timestamppb.New(expirationTime),
				Status:          pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
			}, nil
		}
		manager, err := NewManager(mockSessionClient)
		require.NoError(t, err)
		s, err := manager.LoadLocalSession(context.Background(), "foo", "worker id")
		require.NoError(t, err)
		assert.Equal(t, "foo", s.GetId())
		assert.Equal(t, pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING, s.GetStatus())
		assert.Empty(t, s.GetLocalConnections())
		assert.Equal(t, int32(-1), s.GetConnectionLimit())
		assert.Equal(t, expirationTime, s.GetExpiration())
	})
}

func createTestCert(t *testing.T) []byte {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(0),
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(5 * time.Minute),
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"/tmp/boundary-opslistener-test0.sock", "/tmp/boundary-opslistener-test1.sock"},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	return certBytes
}

func TestWorkerSetCloseTimeForResponse(t *testing.T) {
	cases := []struct {
		name             string
		sessionCloseInfo map[string][]*pbs.CloseConnectionResponseData
		sessionInfoMap   func() *sync.Map
		expected         []string
		expectedClosed   map[string]struct{}
		expectedErr      []error
	}{
		{
			name: "basic",
			sessionCloseInfo: map[string][]*pbs.CloseConnectionResponseData{
				"one": {
					{ConnectionId: "foo", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
				},
				"two": {
					{ConnectionId: "bar", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
				},
			},
			sessionInfoMap: func() *sync.Map {
				m := new(sync.Map)
				m.Store("one", &sess{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "one",
					}},
					connInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})
				m.Store("two", &sess{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "two",
					}},
					connInfoMap: map[string]*ConnInfo{
						"bar": {Id: "bar"},
					},
				})
				m.Store("three", &sess{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "three",
					}},
					connInfoMap: map[string]*ConnInfo{
						"baz": {Id: "baz"},
					},
				})

				return m
			},
			expected: []string{"foo", "bar"},
			expectedClosed: map[string]struct{}{
				"foo": {},
				"bar": {},
			},
		},
		{
			name: "not closed",
			sessionCloseInfo: map[string][]*pbs.CloseConnectionResponseData{
				"one": {
					{ConnectionId: "foo", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
				},
				"two": {
					{ConnectionId: "bar", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED},
				},
			},
			sessionInfoMap: func() *sync.Map {
				m := new(sync.Map)
				m.Store("one", &sess{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "one",
					}},
					connInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})
				m.Store("two", &sess{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "two",
					}},
					connInfoMap: map[string]*ConnInfo{
						"bar": {Id: "bar"},
					},
				})

				return m
			},
			expected: []string{"foo"},
			expectedClosed: map[string]struct{}{
				"foo": {},
			},
		},
		{
			name: "missing session",
			sessionCloseInfo: map[string][]*pbs.CloseConnectionResponseData{
				"one": {
					{ConnectionId: "foo", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
				},
				"two": {
					{ConnectionId: "bar", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
				},
			},
			sessionInfoMap: func() *sync.Map {
				m := new(sync.Map)
				m.Store("one", &sess{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "one",
					}},
					connInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})

				return m
			},
			expected: []string{"foo"},
			expectedClosed: map[string]struct{}{
				"foo": {},
			},
			expectedErr: []error{
				errors.New(`could not find session ID "two" in local state after closing connections`),
			},
		},
		{
			name: "missing connection",
			sessionCloseInfo: map[string][]*pbs.CloseConnectionResponseData{
				"one": {
					{ConnectionId: "foo", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
				},
				"two": {
					{ConnectionId: "bar", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
				},
			},
			sessionInfoMap: func() *sync.Map {
				m := new(sync.Map)
				m.Store("one", &sess{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "one",
					}},
					connInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
					sessionId: "one",
				})
				m.Store("two", &sess{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "two",
					}},
					sessionId: "two",
				})

				return m
			},
			expected: []string{"foo"},
			expectedClosed: map[string]struct{}{
				"foo": {},
			},
			expectedErr: []error{
				errors.New(`could not find connection ID "bar" for session ID "two" in local state`),
			},
		},
		{
			name:             "empty",
			sessionCloseInfo: make(map[string][]*pbs.CloseConnectionResponseData),
			sessionInfoMap: func() *sync.Map {
				m := new(sync.Map)
				m.Store("one", &sess{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "one",
					}},
					connInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})

				return m
			},
			expected:       []string{},
			expectedClosed: map[string]struct{}{},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			manager := &manager{sessionMap: new(sync.Map)}
			manager.sessionMap = tc.sessionInfoMap()
			actual, actualErr := setCloseTimeForResponse(manager, tc.sessionCloseInfo)

			// Assert all close times were set
			manager.ForEachLocalSession(func(value Session) bool {
				t.Helper()
				for _, ci := range value.GetLocalConnections() {
					if _, ok := tc.expectedClosed[ci.Id]; ok {
						require.NotEqual(time.Time{}, ci.CloseTime)
					} else {
						require.Equal(time.Time{}, ci.CloseTime)
					}
				}

				return true
			})

			// Assert return values
			require.ElementsMatch(tc.expected, actual)
			require.ElementsMatch(tc.expectedErr, actualErr)
		})
	}
}
