// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"testing"
)

func TestOmitEmptyArray(t *testing.T) {
	type t1 struct {
		_struct bool `codec:",toarray"`
		B1      bool
	}

	type t2 struct {
		t1
		B2 bool `codec:",omitempty"`
	}

	var x1 t1
	var x2 t2

	b1, err := encodeToBytes(x1)
	if err != nil {
		t.Fatal(err)
	}

	b2, err := encodeToBytes(x2)
	if err != nil {
		t.Fatal(err)
	}

	// Our codec library doesn't honor omitempty for toarray
	// structs.
	if bytes.Equal(b1, b2) {
		t.Fatalf("b1 == b2 = %v", b1)
	}
}
