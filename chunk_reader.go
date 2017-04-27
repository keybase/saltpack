// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

// chunker is an interface for a type that emits a sequence of
// plaintext chunks.
type chunker interface {
	// getNextChunk() returns a plaintext chunk with an error. If
	// the chunk is empty, the error must be non-nil. Once
	// getNextChunk() returns a non-nil error, it can assume that
	// it will never be called again.
	getNextChunk() ([]byte, error)
}

// getNextChunk should look like:
//
// func (c myChunker) getNextChunk() ([]byte, error) {
//	var block myBlock
//	seqno, err := c.mps.Read(&block) // c.mps is a *msgpackStream.
//	if err != nil {
//		// An EOF here is unexpected.
//		if err == io.EOF {
//			err = io.ErrUnexpectedEOF
//		}
//		return nil, err
//	}
//
//	// If processBlock returns a non-nil error, plaintext should be empty.
//	plaintext, err := c.processBlock(block..., seqno)
//	if err != nil {
//		return nil, err
//	}
//
//	// There should be nothing else after a final block.
//	if block.IsFinal {
//		err = assertEndOfStream(c.mps)
//	}
//	return plaintext, err
// }

// chunkReader is an io.Reader adaptor for chunker.
type chunkReader struct {
	chunker   chunker
	prevChunk []byte
	prevErr   error
}

func newChunkReader(chunker chunker) *chunkReader {
	return &chunkReader{chunker: chunker}
}

func (r *chunkReader) Read(p []byte) (n int, err error) {
	// Copy data into p until it is full, or getNextChunk()
	// returns a non-nil error.
	for {
		if len(r.prevChunk) > 0 {
			copied := copy(p[n:], r.prevChunk)
			n += copied
			r.prevChunk = r.prevChunk[copied:]
			if len(r.prevChunk) > 0 {
				// p is full.
				return n, nil
			}
		}

		if r.prevErr != nil {
			// r.prevChunk is fully drained, so return the
			// error.
			return n, r.prevErr
		}

		r.prevChunk, r.prevErr = r.chunker.getNextChunk()
		if len(r.prevChunk) == 0 && r.prevErr == nil {
			panic("empty chunk and nil error")
		}
	}
}
