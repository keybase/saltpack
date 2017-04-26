// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import "fmt"

type chunker interface {
	// If getNextChunk returns a non-nil error, the returned chunk
	// must be empty.
	//
	// TODO: Add a condition that if getNextChunk() returns an
	// empty chunk and a nil error on first call, the next call
	// must return an empty chunk and a non-nil error.
	getNextChunk() ([]byte, error)
}

type chunkReader struct {
	chunker chunker
	// Invariant: If prevErr is non-nil, prevChunk is empty.
	prevChunk []byte
	prevErr   error
}

func newChunkReader(chunker chunker) *chunkReader {
	return &chunkReader{chunker: chunker}
}

func (r *chunkReader) Read(p []byte) (n int, err error) {
	for r.prevErr == nil {
		if len(r.prevChunk) > 0 {
			copied := copy(p[n:], r.prevChunk)
			n += copied
			r.prevChunk = r.prevChunk[copied:]
			if len(r.prevChunk) > 0 {
				break
			}
		}

		r.prevChunk, r.prevErr = r.chunker.getNextChunk()
		if len(r.prevChunk) > 0 && r.prevErr != nil {
			panic(fmt.Sprintf("getNextChunk() returned buffer of size %d with err=%v", len(r.prevChunk), r.prevErr))
		}
	}

	return n, r.prevErr
}
