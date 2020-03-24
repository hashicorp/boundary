package any

import (
	"bytes"
	"io"
	"testing"

	"github.com/matryer/is"
)

// Test_QueueBuffer provides basic tests for the QueueBuffer type
func Test_QueueBuffer(t *testing.T) {
	t.Parallel()
	is := is.New(t)
	b := QueueBuffer{}

	_, err := b.Write([]byte("bye"))
	is.NoErr(err)
	is.True(b.Len() == len([]byte("bye")))

	_, err = b.Write([]byte("hello"))
	is.NoErr(err)
	is.True(b.Len() == len([]byte("bye"))+len([]byte("hello")))

	bye := make([]byte, 3)
	_, err = b.Read(bye)
	is.NoErr(err)
	is.True(bytes.Equal(bye, []byte("bye")))

	hello := b.Next(len([]byte("hello")))
	is.True(bytes.Equal(hello, []byte("hello")))

	t.Log(string(hello))
	t.Log(string(bye))

	nada := make([]byte, 4)
	_, err = b.Read(nada)
	is.True(err == io.EOF)

	nothin := b.Next(len([]byte("nothin")))
	is.True(nothin == nil)

}
