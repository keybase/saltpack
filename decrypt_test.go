// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import "testing"

func TestVersionValidator(t *testing.T) {
	plaintext := []byte{0x01}
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	ciphertext, err := Seal(Version1(), plaintext, sender, receivers)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = Open(SingleVersionValidator(Version2()), ciphertext, kr)
	if err == nil {
		t.Fatal("Unexpected nil error")
	}
}

func testNewMinorVersion(t *testing.T, version Version) {
	plaintext := []byte{0x01}

	newVersion := version
	newVersion.Minor++

	teo := testEncryptionOptions{
		corruptHeader: func(_ []int, eh *EncryptionHeader) {
			eh.Version = newVersion
		},
	}
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	ciphertext, err := testSeal(version, plaintext, sender, receivers, teo)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = Open(SingleVersionValidator(newVersion), ciphertext, kr)
	if err != nil {
		t.Fatalf("Unepected error %v", err)
	}
}

func TestDecrypt(t *testing.T) {
	tests := []func(*testing.T, Version){
		testNewMinorVersion,
	}
	runTestsOverVersions(t, "test", tests)
}
