// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

type chunker interface {
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
	for {
		if len(r.prevChunk) > 0 {
			copied := copy(p[n:], r.prevChunk)
			n += copied
			r.prevChunk = r.prevChunk[copied:]
			if len(r.prevChunk) > 0 {
				return n, nil
			}
		}

		if r.prevErr != nil {
			return n, r.prevErr
		}

		r.prevChunk, r.prevErr = r.chunker.getNextChunk()
	}
}
