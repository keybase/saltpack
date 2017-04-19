// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package basex

import (
	"errors"
	"testing"
)

type fakeReader struct {
	b   byte
	n   int
	err error
}

func (r fakeReader) Read(b []byte) (int, error) {
	for i := 0; i < r.n; i++ {
		b[i] = r.b
	}
	return r.n, r.err
}

func TestDecodeReaderError(t *testing.T) {
	fakeErr := errors.New("fake error")
	encoding := Base58StdEncoding
	decoder := NewDecoder(Base58StdEncoding, fakeReader{'1', encoding.baseXBlockLen, fakeErr})
	var buf [100]byte
	_, err := decoder.Read(buf[:])
	if err != fakeErr {
		t.Fatalf("Expected %v, got %v", fakeErr, err)
	}
}
