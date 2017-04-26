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
	chunks   [][]byte
	finalErr error
}

func (s *testChunker) getNextChunk() ([]byte, error) {
	if len(s.chunks) == 0 {
		return nil, s.finalErr
	}

	chunk := s.chunks[0]
	s.chunks = s.chunks[1:]
	return chunk, nil
}

func chunkString(s string, chunkSize int, finalErr error) *testChunker {
	var chunks [][]byte
	for len(s) > 0 {
		n := chunkSize
		if n > len(s) {
			n = len(s)
		}
		chunks = append(chunks, []byte(s[:n]))
		s = s[n:]
	}
	return &testChunker{chunks, finalErr}
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

func testChunkReader(t *testing.T, s string, chunkSize, readSize int, finalErr error) {
	chunker := chunkString(s, chunkSize, finalErr)
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
	for _, input := range inputs {
		// Capture range variable.
		input := input
		t.Run(fmt.Sprintf("input=%q", input), func(t *testing.T) {
			testChunkReader(t, input, 2, 1, errors.New("test error"))
		})
	}
}
