// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"sync"
	"testing"
)

func TestVerifyVersionValidator(t *testing.T) {
	in := []byte{0x01}
	key := newSigPrivKey(t)
	smg, err := Sign(Version1(), in, key)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = Verify(SingleVersionValidator(Version2()), smg, kr)
	if err == nil {
		t.Fatal("Unexpected nil error")
	}
}

func testVerify(t *testing.T, version Version) {
	in := randomMsg(t, 128)
	key := newSigPrivKey(t)
	smsg, err := Sign(version, in, key)
	if err != nil {
		t.Fatal(err)
	}
	skey, msg, err := Verify(SingleVersionValidator(version), smsg, kr)
	if err != nil {
		t.Logf("input:      %x", in)
		t.Logf("signed msg: %x", smsg)
		t.Fatal(err)
	}
	if !PublicKeyEqual(skey, key.GetPublicKey()) {
		t.Errorf("sender key %x, expected %x", skey.ToKID(), key.GetPublicKey().ToKID())
	}
	if !bytes.Equal(msg, in) {
		t.Errorf("verified msg '%x', expected '%x'", msg, in)
	}
}

func testVerifyNewMinorVersion(t *testing.T, version Version) {
	in := []byte{0x01}

	newVersion := version
	newVersion.Minor++

	tso := testSignOptions{
		corruptHeader: func(sh *SignatureHeader) {
			sh.Version = newVersion
		},
	}
	key := newSigPrivKey(t)
	smg, err := testTweakSign(version, in, key, tso)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = Verify(SingleVersionValidator(newVersion), smg, kr)
	if err != nil {
		t.Fatalf("Unepected error %v", err)
	}
}

func testVerifyConcurrent(t *testing.T, version Version) {
	in := randomMsg(t, 128)
	key := newSigPrivKey(t)
	smsg, err := Sign(version, in, key)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			skey, msg, err := Verify(SingleVersionValidator(version), smsg, kr)
			if err != nil {
				t.Logf("input:      %x", in)
				t.Logf("signed msg: %x", smsg)
				t.Error(err)
				// Don't fall through, as the tests below will panic.
				return
			}
			if !PublicKeyEqual(skey, key.GetPublicKey()) {
				t.Errorf("sender key %x, expected %x", skey.ToKID(), key.GetPublicKey().ToKID())
			}
			if !bytes.Equal(msg, in) {
				t.Errorf("verified msg '%x', expected '%x'", msg, in)
			}
		}()
	}
	wg.Wait()
}

type emptySigKeyring struct{}

func (k emptySigKeyring) LookupSigningPublicKey(kid []byte) SigningPublicKey { return nil }

func testVerifyEmptyKeyring(t *testing.T, version Version) {
	in := randomMsg(t, 128)
	key := newSigPrivKey(t)
	smsg, err := Sign(version, in, key)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = Verify(SingleVersionValidator(version), smsg, emptySigKeyring{})
	if err == nil {
		t.Fatal("Verify worked with empty keyring")
	}
	if err != ErrNoSenderKey {
		t.Errorf("error: %v, expected ErrNoSenderKey", err)
	}
}

func testVerifyDetachedEmptyKeyring(t *testing.T, version Version) {
	key := newSigPrivKey(t)
	msg := randomMsg(t, 128)
	sig, err := SignDetached(version, msg, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyDetached(SingleVersionValidator(version), msg, sig, emptySigKeyring{})
	if err == nil {
		t.Fatal("VerifyDetached worked with empty keyring")
	}
	if err != ErrNoSenderKey {
		t.Errorf("error: %v, expected ErrNoSenderKey", err)
	}
}

func testVerifyErrorAtEOF(t *testing.T, version Version) {
	in := randomMsg(t, 128)
	key := newSigPrivKey(t)
	smsg, err := Sign(version, in, key)
	if err != nil {
		t.Fatal(err)
	}

	var reader io.Reader = bytes.NewReader(smsg)
	errAtEOF := errors.New("err at EOF")
	reader = errAtEOFReader{reader, errAtEOF}
	_, stream, err := NewVerifyStream(SingleVersionValidator(version), reader, kr)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := ioutil.ReadAll(stream)
	if err != errAtEOF {
		t.Fatalf("err=%v != errAtEOF=%v", err, errAtEOF)
	}

	// Since the bytes are still verified, the verified message
	// should still compare equal to the original input.
	if !bytes.Equal(msg, in) {
		t.Errorf("verified msg '%x', expected '%x'", msg, in)
	}
}

func TestVerify(t *testing.T) {
	tests := []func(*testing.T, Version){
		testVerify,
		testVerifyNewMinorVersion,
		testVerifyConcurrent,
		testVerifyEmptyKeyring,
		testVerifyDetachedEmptyKeyring,
		testVerifyErrorAtEOF,
	}
	runTestsOverVersions(t, "test", tests)
}
