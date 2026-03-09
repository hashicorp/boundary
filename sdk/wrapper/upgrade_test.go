// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package wrapper

// NOTE: The test below is commented out for a very specific reason: to not
// bring in all of the v1 dependencies, since the major driving force behind v2
// is to not pull in all cloud deps. However, this test is left here for anyone
// wanting to validate compatibility as that's useful.

// Needed imports:
/*
	wrapping "github.com/hashicorp/go-kms-wrapping"
	wrappingv2 "github.com/hashicorp/go-kms-wrapping/v2"
	aeadv1 "github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	aeadv2 "github.com/hashicorp/go-kms-wrapping/wrappers/v2/aead"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
*/

/*
// TestGkwV1V2Upgrade creates a message with v1 and validates that we can read
// it with v2, and vice versa
func TestGkwV1V2Upgrade(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Create two wrappers and set key bytes the same
	v1Wrapper := aeadv1.NewWrapper(nil)
	v2Wrapper := TestWrapper(t).(*aeadv2.Wrapper)
	require.NoError(v1Wrapper.SetAESGCMKeyBytes(v2Wrapper.GetKeyBytes()))

	// Encrypt with v1
	v1Blob, err := v1Wrapper.Encrypt(ctx, []byte("foo"), []byte("bar"))
	require.NoError(err)
	v1BlobMsg, err := proto.Marshal(v1Blob)
	require.NoError(err)
	require.NotNil(v1BlobMsg)
	// Read with v2
	v2Blob := new(wrappingv2.BlobInfo)
	require.NoError(proto.Unmarshal(v1BlobMsg, v2Blob))
	pt, err := v2Wrapper.Decrypt(ctx, v2Blob, wrappingv2.WithAad([]byte("bar")))
	require.NoError(err)
	require.Equal([]byte("foo"), pt)

	// Now encrypt with v2
	v2Blob, err = v2Wrapper.Encrypt(ctx, []byte("bar"), wrappingv2.WithAad([]byte("foo")))
	require.NoError(err)
	v2BlobMsg, err := proto.Marshal(v2Blob)
	require.NoError(err)
	require.NotNil(v2BlobMsg)
	// Read with v1
	v1Blob = new(wrapping.EncryptedBlobInfo)
	require.NoError(proto.Unmarshal(v2BlobMsg, v1Blob))
	pt, err = v1Wrapper.Decrypt(ctx, v1Blob, []byte("foo"))
	require.NoError(err)
	require.Equal([]byte("bar"), pt)
}
*/
