// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"testing"
)

func TestDecryptVersionValidator(t *testing.T) {
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
		corruptHeader: func(eh *EncryptionHeader) {
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

type errAtEOFReader struct {
	io.Reader
	errAtEOF error
}

func (r errAtEOFReader) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	if err == io.EOF {
		err = r.errAtEOF
	}
	return n, err
}

func testDecryptErrorAtEOF(t *testing.T, version Version) {
	plaintext := randomMsg(t, 128)
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	ciphertext, err := Seal(version, plaintext, sender, receivers)
	if err != nil {
		t.Fatal(err)
	}

	var reader io.Reader = bytes.NewReader(ciphertext)
	errAtEOF := errors.New("err at EOF")
	reader = errAtEOFReader{reader, errAtEOF}
	_, stream, err := NewDecryptStream(SingleVersionValidator(version), reader, kr)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := ioutil.ReadAll(stream)
	if err != errAtEOF {
		t.Fatalf("err=%v != errAtEOF=%v", err, errAtEOF)
	}

	// Since the bytes are still authenticated, the decrypted
	// message should still compare equal to the original input.
	if !bytes.Equal(msg, plaintext) {
		t.Errorf("decrypted msg '%x', expected '%x'", msg, plaintext)
	}
}

func TestDecrypt(t *testing.T) {
	tests := []func(*testing.T, Version){
		testNewMinorVersion,
		testDecryptErrorAtEOF,
	}
	runTestsOverVersions(t, "test", tests)
}
