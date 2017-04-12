// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import "testing"

func TestVersionValidator(t *testing.T) {
	plaintext := []byte{0x01}
	sndr := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	ciphertext, err := Seal(Version1(), plaintext, sndr, receivers)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = Open(SingleVersionValidator(Version2()), ciphertext, kr)
	if err == nil {
		t.Fatal("Unexpected nil error")
	}
}
