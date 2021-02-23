package oidc

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_validateFieldMask(t *testing.T) {
	tests := []struct {
		name      string
		fieldMask []string
		wantErr   bool
	}{
		{
			name: "all-valid-fields",
			fieldMask: []string{
				"Name",
				"Description",
				"OperationalState",
				"DiscoveryUrl",
				"ClientId",
				"ClientSecret",
				"MaxAge",
				"SigningAlgs",
				"CallbackUrls",
				"AudClaims",
				"Certificates",
			},
		},
		{
			name:      "invalid",
			fieldMask: []string{"Invalid", "Name"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			err := validateFieldMask(tt.fieldMask)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
		})
	}
}

func Test_applyUpdate(t *testing.T) {
	tests := []struct {
		name      string
		new       *AuthMethod
		orig      *AuthMethod
		fieldMask []string
		want      *AuthMethod
	}{
		{
			name: "valid-all-fields",
			new: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "new-name",
					Description:      "new-description",
					OperationalState: string(ActivePublicState),
					DiscoveryUrl:     "new-discovery-url",
					ClientId:         "new-client-id",
					ClientSecret:     "new-client-secret",
					MaxAge:           100,
					SigningAlgs:      []string{"new-alg1", "new-alg2"},
					CallbackUrls:     []string{"new-callback-1", "new-callback-2"},
					AudClaims:        []string{"new-aud-1", "new-aud-2"},
					Certificates:     []string{"new-pem1", "new-pem-2"},
				},
			},
			orig: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "orig-name",
					Description:      "orig-description",
					OperationalState: string(InactiveState),
					DiscoveryUrl:     "orig-discovery-url",
					ClientId:         "orig-client-id",
					ClientSecret:     "orig-client-secret",
					MaxAge:           100,
					SigningAlgs:      []string{"orig-alg1", "orig-alg2"},
					CallbackUrls:     []string{"orig-callback-1", "orig-callback-2"},
					AudClaims:        []string{"orig-aud-1", "orig-aud-2"},
					Certificates:     []string{"orig-pem1", "orig-pem-2"},
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "new-name",
					Description:      "new-description",
					OperationalState: string(ActivePublicState),
					DiscoveryUrl:     "new-discovery-url",
					ClientId:         "new-client-id",
					ClientSecret:     "new-client-secret",
					MaxAge:           100,
					SigningAlgs:      []string{"new-alg1", "new-alg2"},
					CallbackUrls:     []string{"new-callback-1", "new-callback-2"},
					AudClaims:        []string{"new-aud-1", "new-aud-2"},
					Certificates:     []string{"new-pem1", "new-pem-2"},
				},
			},
			fieldMask: []string{
				"Name",
				"Description",
				"OperationalState",
				"DiscoveryUrl",
				"ClientId",
				"ClientSecret",
				"MaxAge",
				"SigningAlgs",
				"CallbackUrls",
				"AudClaims",
				"Certificates",
			},
		},
		{
			name: "nil-value-objects",
			new: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "new-name",
					Description:      "new-description",
					OperationalState: string(ActivePublicState),
					DiscoveryUrl:     "new-discovery-url",
					ClientId:         "new-client-id",
					ClientSecret:     "new-client-secret",
					MaxAge:           100,
				},
			},
			orig: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "orig-name",
					Description:      "orig-description",
					OperationalState: string(InactiveState),
					DiscoveryUrl:     "orig-discovery-url",
					ClientId:         "orig-client-id",
					ClientSecret:     "orig-client-secret",
					MaxAge:           100,
					SigningAlgs:      []string{"orig-alg1", "orig-alg2"},
					CallbackUrls:     []string{"orig-callback-1", "orig-callback-2"},
					AudClaims:        []string{"orig-aud-1", "orig-aud-2"},
					Certificates:     []string{"orig-pem1", "orig-pem-2"},
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "new-name",
					Description:      "new-description",
					OperationalState: string(ActivePublicState),
					DiscoveryUrl:     "new-discovery-url",
					ClientId:         "new-client-id",
					ClientSecret:     "new-client-secret",
					MaxAge:           100,
				},
			},
			fieldMask: []string{
				"Name",
				"Description",
				"OperationalState",
				"DiscoveryUrl",
				"ClientId",
				"ClientSecret",
				"MaxAge",
				"SigningAlgs",
				"CallbackUrls",
				"AudClaims",
				"Certificates",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := applyUpdate(tt.new, tt.orig, tt.fieldMask)
			assert.Equal(got, tt.want)
		})
	}
}

type mockClient struct {
	mockDo func(req *http.Request) (*http.Response, error)
}

// Overriding what the Do function should "do" in our MockClient
func (m *mockClient) Do(req *http.Request) (*http.Response, error) {
	return m.mockDo(req)
}

func Test_pingEndpoint(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		setup   func() (HTTPClient, string, string)
		wantErr bool
	}{
		{
			name: "valid-endpoint",
			setup: func() (HTTPClient, string, string) {
				client := &mockClient{
					mockDo: func(*http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 200,
						}, nil
					},
				}
				return client, http.MethodGet, "http://localhost/get"
			},
		},
		{
			name: "valid-500",
			setup: func() (HTTPClient, string, string) {
				client := &mockClient{
					mockDo: func(*http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 500,
						}, nil
					},
				}
				return client, http.MethodGet, "http://localhost/get"
			},
		},
		{
			name: "failed",
			setup: func() (HTTPClient, string, string) {
				client := &mockClient{
					mockDo: func(*http.Request) (*http.Response, error) {
						return nil, fmt.Errorf("invalid request")
					},
				}
				return client, http.MethodGet, "http://localhost/get"
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			client, method, url := tt.setup()
			err := pingEndpoint(ctx, client, tt.name, method, url)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
		})
	}
}
