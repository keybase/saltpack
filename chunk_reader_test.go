// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testChunker struct {
	t                *testing.T
	chunks           [][]byte
	finalErr         error
	errWithLastChunk bool
	finalErrHit      bool
}

func (c *testChunker) getNextChunk() ([]byte, error) {
	if c.finalErrHit {
		c.t.Fatal("getNextChunk() called with finalErrHit set")
	}

	if len(c.chunks) == 0 {
		// c.errWithLastChunk can still be set here if call
		// chunkString with the empty string.
		c.finalErrHit = true
		return nil, c.finalErr
	}

	chunk := c.chunks[0]
	c.chunks = c.chunks[1:]
	if c.errWithLastChunk && len(c.chunks) == 0 {
		c.finalErrHit = true
		return chunk, c.finalErr
	}
	return chunk, nil
}

func chunkString(t *testing.T, s string, chunkSize int, finalErr error, errWithLastChunk bool) *testChunker {
	var chunks [][]byte
	for len(s) > 0 {
		n := chunkSize
		if n > len(s) {
			n = len(s)
		}
		chunks = append(chunks, []byte(s[:n]))
		s = s[n:]
	}
	return &testChunker{t, chunks, finalErr, errWithLastChunk, false}
}

func testReadAll(t *testing.T, r io.Reader, readSize int) ([]byte, error) {
	var out []byte
	buf := make([]byte, readSize)
	for {
		n, err := r.Read(buf)
		if err == nil {
			assert.Equal(t, readSize, n)
		}
		out = append(out, buf[:n]...)
		if err != nil {
			return out, err
		}
	}
}

func testChunkReader(t *testing.T, s string, chunkSize, readSize int, finalErr error, errWithLastChunk bool) {
	chunker := chunkString(t, s, chunkSize, finalErr, errWithLastChunk)
	r := newChunkReader(chunker)
	out, err := testReadAll(t, r, readSize)
	require.Equal(t, finalErr, err)
	require.Equal(t, s, string(out))
}

func TestChunkReader(t *testing.T) {
	inputs := []string{
		"hello world",
		"",
		"somewhat long string",
	}
	sizes := []int{1, 3, 5, 1024}
	errs := []error{
		errors.New("test error"),
		io.EOF,
	}
	for _, input := range inputs {
		for _, chunkSize := range sizes {
			for _, readSize := range sizes {
				for _, err := range errs {
					// Capture range variables.
					input := input
					chunkSize := chunkSize
					readSize := readSize
					finalErr := err
					t.Run(fmt.Sprintf("input=%q,chunkSize=%d,readSize=%d,finalErr=%v,errWithLastChunk=false", input, chunkSize, readSize, finalErr), func(t *testing.T) {
						testChunkReader(t, input, chunkSize, readSize, finalErr, false)
					})
					t.Run(fmt.Sprintf("input=%q,chunkSize=%d,readSize=%d,finalErr=%v,errWithLastChunk=true", input, chunkSize, readSize, finalErr), func(t *testing.T) {
						testChunkReader(t, input, chunkSize, readSize, finalErr, true)
					})
				}
			}
		}
	}
}

func TestChunkReaderEmptyRead(t *testing.T) {
	s := "hello world"
	chunker := chunkString(t, s, 5, io.EOF, false)
	r := newChunkReader(chunker)

	n, err := r.Read(nil)
	require.NoError(t, err)
	require.Equal(t, 0, n)

	out, err := testReadAll(t, r, 1)
	require.Equal(t, io.EOF, err)
	require.Equal(t, s, string(out))

	n, err = r.Read(nil)
	require.Equal(t, io.EOF, err)
	require.Equal(t, 0, n)
}
