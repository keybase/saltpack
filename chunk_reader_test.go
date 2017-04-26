// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"errors"
	"io/ioutil"
	"testing"

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

func testChunkReader(t *testing.T, s string, chunkSize, readSize int, finalErr error) {
	chunker := chunkString(s, chunkSize, finalErr)
	r := newChunkReader(chunker)
	out, err := ioutil.ReadAll(r)
	require.Equal(t, finalErr, err)
	require.Equal(t, s, string(out))
}

func TestChunkReader(t *testing.T) {
	testChunkReader(t, "hello world", 2, 1, errors.New("test error"))
}
