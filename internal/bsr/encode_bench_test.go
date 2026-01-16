// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
)

type testChunk struct {
	*BaseChunk
	Data []byte
}

// MarshalData serializes the data portion of a chunk.
func (t *testChunk) MarshalData(_ context.Context) ([]byte, error) {
	return t.Data, nil
}

func newTestChunk(d int) *testChunk {
	data := make([]byte, d)
	ts := time.Date(2023, time.March, 16, 10, 47, 3, 14, time.UTC)
	return &testChunk{
		BaseChunk: &BaseChunk{
			Protocol:  "TEST",
			Direction: Inbound,
			Timestamp: NewTimestamp(ts),
			Type:      "TEST",
		},
		Data: data,
	}
}

func BenchmarkEncodeParallel(b *testing.B) {
	b.ReportAllocs()
	cases := []int{16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}
	for _, chunkSize := range cases {
		b.StopTimer()
		ctx := context.Background()
		chunks := make([]Chunk, 250)
		for i := range chunks {
			chunks[i] = newTestChunk(chunkSize)
		}
		b.StartTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf, err := fstest.NewTempBuffer()
				if err != nil {
					b.Fatal("could not create buffer")
				}
				enc, _ := NewChunkEncoder(ctx, buf, NoCompression, NoEncryption)
				for _, c := range chunks {
					if _, err := enc.Encode(ctx, c); err != nil {
						b.Fatal("Encode:", err)
					}
				}
				b.SetBytes(int64(len(buf.Bytes())))
			}
		})
	}
}

func BenchmarkEncodeSequential(b *testing.B) {
	cases := []int{16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}
	for _, chunkSize := range cases {
		b.Run(fmt.Sprintf("%d", chunkSize), func(b *testing.B) {
			b.ReportAllocs()
			b.StopTimer()
			ctx := context.Background()
			chunks := make([]Chunk, 250)
			for i := range chunks {
				chunks[i] = newTestChunk(chunkSize)
			}
			b.StartTimer()

			for i := 0; i < b.N; i++ {
				buf, err := fstest.NewTempBuffer()
				if err != nil {
					b.Fatal("could not create buffer")
				}
				enc, _ := NewChunkEncoder(ctx, buf, NoCompression, NoEncryption)
				for _, c := range chunks {
					if _, err := enc.Encode(ctx, c); err != nil {
						b.Fatal("Encode:", err)
					}
				}
				b.SetBytes(int64(len(buf.Bytes())))
			}
		})
	}
}
