package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/stretchr/testify/require"
)

func TestCache_RefreshSession(t *testing.T) {
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
			cache := NewCache(mockSessionClient)
			s, err := cache.RefreshSession(context.Background(), tc.inId, tc.inWorkerId)
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
		cache := NewCache(mockSessionClient)
		s, err := cache.RefreshSession(context.Background(), "foo", "worker id")
		require.NoError(t, err)
		assert.Equal(t, "foo", s.GetId())
		assert.Equal(t, pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING, s.GetStatus())
		assert.Empty(t, s.GetConnections())
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
				m.Store("one", &Session{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "one",
					}},
					connInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})
				m.Store("two", &Session{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "two",
					}},
					connInfoMap: map[string]*ConnInfo{
						"bar": {Id: "bar"},
					},
				})
				m.Store("three", &Session{
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
				m.Store("one", &Session{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "one",
					}},
					connInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})
				m.Store("two", &Session{
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
				m.Store("one", &Session{
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
				m.Store("one", &Session{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "one",
					}},
					connInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})
				m.Store("two", &Session{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "two",
					}},
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
				m.Store("one", &Session{
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
			cache := NewCache(nil)
			cache.sessionMap = tc.sessionInfoMap()
			actual, actualErr := setCloseTimeForResponse(cache, tc.sessionCloseInfo)

			// Assert all close times were set
			cache.ForEachSession(func(value *Session) bool {
				t.Helper()
				for _, ci := range value.GetConnections() {
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
