// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

type chunkStreamer interface {
	// If getNextChunk returns a non-nil error, the returned chunk
	// must be empty.
	//
	// TODO: Add a condition that if getNextChunk() returns an
	// empty chunk and a nil error on first call, the next call
	// must return an empty chunk and a non-nil error.
	getNextChunk() ([]byte, error)
}

type chunkReader struct {
	streamer chunkStreamer
	// Invariant: If prevErr is non-nil, prevChunk is empty.
	prevChunk []byte
	prevErr   error
}

func (r *chunkReader) Read(p []byte) (n int, err error) {
	for r.prevErr == nil {
		if len(r.prevChunk) > 0 {
			copied := copy(p[n:], r.prevChunk)
			n += copied
			r.prevChunk = r.prevChunk[copied:]
			if len(r.prevChunk) > 0 {
				return n, nil
			}
		}

		// TODO: Check conditions on getNextChunk().
		r.prevChunk, r.prevErr = r.streamer.getNextChunk()
	}

	return n, r.prevErr
}
