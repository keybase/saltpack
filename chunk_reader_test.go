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

// chunkString chunks s up into pieces of size chunkSize, then returns
// a testChunker to emit those chunks.
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

// readAll reads all data from r with the given buffer size.
func readAll(t *testing.T, r io.Reader, bufSize int) ([]byte, error) {
	var out []byte
	buf := make([]byte, bufSize)
	for {
		n, err := r.Read(buf)
		if err == nil {
			assert.Equal(t, bufSize, n)
		}
		out = append(out, buf[:n]...)
		if err != nil {
			return out, err
		}
	}
}

func testChunkReader(t *testing.T, s string, chunkSize, bufSize int, finalErr error, errWithLastChunk bool) {
	chunker := chunkString(t, s, chunkSize, finalErr, errWithLastChunk)
	r := newChunkReader(chunker)
	out, err := readAll(t, r, bufSize)
	require.Equal(t, finalErr, err)
	require.Equal(t, s, string(out))
}

func TestChunkReader(t *testing.T) {
	inputs := []string{
		"",
		"hello world",
		"somewhat long string",
		string(make([]byte, 1024)),
	}

	sizes := []int{1, 3, 5, 1024}

	errs := []error{
		errors.New("test error"),
		io.EOF,
	}

	for _, input := range inputs {
		for _, chunkSize := range sizes {
			for _, bufSize := range sizes {
				for _, finalErr := range errs {
					for _, errWithLastChunk := range []bool{false, true} {
						// Capture range variables.
						input := input
						chunkSize := chunkSize
						bufSize := bufSize
						finalErr := finalErr
						errWithLastChunk := errWithLastChunk

						var inputName string
						if len(input) > 5 {
							inputName = fmt.Sprintf("string(%d)", len(input))
						} else {
							inputName = fmt.Sprintf("%q", input)
						}
						name := fmt.Sprintf("input=%s,chunkSize=%d,bufSize=%d,finalErr=%v,errWithLastChunk=%t", inputName, chunkSize, bufSize, finalErr, errWithLastChunk)
						t.Run(name, func(t *testing.T) {
							testChunkReader(t, input, chunkSize, bufSize, finalErr, errWithLastChunk)
						})
					}
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

	out, err := readAll(t, r, 1)
	require.Equal(t, io.EOF, err)
	require.Equal(t, s, string(out))

	n, err = r.Read(nil)
	require.Equal(t, io.EOF, err)
	require.Equal(t, 0, n)
}
