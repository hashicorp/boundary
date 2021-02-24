package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_valueObjectChanges(t *testing.T) {
	t.Parallel()
	_, pem1 := testGenerateCA(t, "localhost")
	_, pem2 := testGenerateCA(t, "127.0.0.1")
	_, pem3 := testGenerateCA(t, "www.example.com")
	tests := []struct {
		name       string
		factory    func(string, interface{}) (interface{}, error)
		id         string
		voName     voName
		new        []string
		old        []string
		dbMask     []string
		nullFields []string
		wantAdd    []interface{}
		wantDel    []interface{}
		wantErr    bool
	}{
		{
			name: string(SigningAlgVO),
			factory: func(publicId string, i interface{}) (interface{}, error) {
				str := fmt.Sprintf("%s", i)
				return NewSigningAlg(publicId, Alg(str))
			},
			id:     "am-public-id",
			voName: SigningAlgVO,
			new:    []string{"ES256", "ES384"},
			old:    []string{"RS256", "RS384", "RS512"},
			dbMask: []string{string(SigningAlgVO)},
			wantAdd: func() []interface{} {
				a, err := NewSigningAlg("am-public-id", ES256)
				require.NoError(t, err)
				a2, err := NewSigningAlg("am-public-id", ES384)
				require.NoError(t, err)
				return []interface{}{a, a2}
			}(),
			wantDel: func() []interface{} {
				a, err := NewSigningAlg("am-public-id", RS256)
				require.NoError(t, err)
				a2, err := NewSigningAlg("am-public-id", RS384)
				require.NoError(t, err)
				a3, err := NewSigningAlg("am-public-id", RS512)
				require.NoError(t, err)
				return []interface{}{a, a2, a3}
			}(),
		},
		{
			name: string(CertificateVO),
			factory: func(publicId string, i interface{}) (interface{}, error) {
				str := fmt.Sprintf("%s", i)
				return NewCertificate(publicId, str)
			},
			id:     "am-public-id",
			voName: CertificateVO,
			new:    []string{pem1, pem2},
			old:    []string{pem3},
			dbMask: []string{string(CertificateVO)},
			wantAdd: func() []interface{} {
				c, err := NewCertificate("am-public-id", pem1)
				require.NoError(t, err)
				c2, err := NewCertificate("am-public-id", pem2)
				require.NoError(t, err)
				return []interface{}{c, c2}
			}(),
			wantDel: func() []interface{} {
				c, err := NewCertificate("am-public-id", pem3)
				require.NoError(t, err)
				return []interface{}{c}
			}(),
		},
		{
			name: string(AudClaimVO),
			factory: func(publicId string, i interface{}) (interface{}, error) {
				str := fmt.Sprintf("%s", i)
				return NewAudClaim(publicId, str)
			},
			id:     "am-public-id",
			voName: AudClaimVO,
			new:    []string{"new-aud1", "new-aud2"},
			old:    []string{"old-aud1", "old-aud2", "old-aud3"},
			dbMask: []string{string(AudClaimVO)},
			wantAdd: func() []interface{} {
				a, err := NewAudClaim("am-public-id", "new-aud1")
				require.NoError(t, err)
				a2, err := NewAudClaim("am-public-id", "new-aud2")
				require.NoError(t, err)
				return []interface{}{a, a2}
			}(),
			wantDel: func() []interface{} {
				a, err := NewAudClaim("am-public-id", "old-aud1")
				require.NoError(t, err)
				a2, err := NewAudClaim("am-public-id", "old-aud2")
				require.NoError(t, err)
				a3, err := NewAudClaim("am-public-id", "old-aud3")
				require.NoError(t, err)
				return []interface{}{a, a2, a3}
			}(),
		},
		{
			name: string(CallbackUrlVO),
			factory: func(publicId string, i interface{}) (interface{}, error) {
				u, err := url.Parse(fmt.Sprintf("%s", i))
				require.NoError(t, err)
				return NewCallbackUrl(publicId, u)
			},
			id:     "am-public-id",
			voName: CallbackUrlVO,
			new:    []string{"http://new-1.com/callback", "http://new-2.com/callback"},
			old:    []string{"http://old-1.com/callback", "http://old-2.com/callback", "http://old-3.com/callback"},
			dbMask: []string{string(CallbackUrlVO)},
			wantAdd: func() []interface{} {
				u, err := url.Parse("http://new-1.com/callback")
				require.NoError(t, err)
				c, err := NewCallbackUrl("am-public-id", u)
				require.NoError(t, err)
				u2, err := url.Parse("http://new-2.com/callback")
				require.NoError(t, err)
				c2, err := NewCallbackUrl("am-public-id", u2)
				require.NoError(t, err)
				return []interface{}{c, c2}
			}(),
			wantDel: func() []interface{} {
				u, err := url.Parse("http://old-1.com/callback")
				require.NoError(t, err)
				c, err := NewCallbackUrl("am-public-id", u)
				require.NoError(t, err)
				u2, err := url.Parse("http://old-2.com/callback")
				require.NoError(t, err)
				c2, err := NewCallbackUrl("am-public-id", u2)
				require.NoError(t, err)
				u3, err := url.Parse("http://old-3.com/callback")
				require.NoError(t, err)
				c3, err := NewCallbackUrl("am-public-id", u3)
				require.NoError(t, err)
				return []interface{}{c, c2, c3}
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotAdd, gotDel, err := valueObjectChanges(tt.factory, tt.id, tt.voName, tt.new, tt.old, tt.dbMask, tt.nullFields)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantAdd, gotAdd)

			switch tt.voName {
			case CertificateVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*Certificate).Cert < bb.(*Certificate).Cert
				})
			case SigningAlgVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*SigningAlg).Alg < bb.(*SigningAlg).Alg
				})
			case CallbackUrlVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*CallbackUrl).Url < bb.(*CallbackUrl).Url
				})
			case AudClaimVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*AudClaim).Aud < bb.(*AudClaim).Aud
				})
			}
			assert.Equalf(tt.wantDel, gotDel, "wantDel: %s\ngotDel:  %s\n", tt.wantDel, gotDel)
		})
	}
}

func Test_validateFieldMask(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
