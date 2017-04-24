// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"sync"
	"testing"
)

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
			skey, msg, err := Verify(SingleVersionValidator(version), smsg, kr)
			if err != nil {
				t.Logf("input:      %x", in)
				t.Logf("signed msg: %x", smsg)
				t.Error(err)
			}
			if !PublicKeyEqual(skey, key.GetPublicKey()) {
				t.Errorf("sender key %x, expected %x", skey.ToKID(), key.GetPublicKey().ToKID())
			}
			if !bytes.Equal(msg, in) {
				t.Errorf("verified msg '%x', expected '%x'", msg, in)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

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

type emptySigKeyring struct{}

func (k emptySigKeyring) LookupSigningPublicKey(kid []byte) SigningPublicKey { return nil }

func TestVerify(t *testing.T) {
	tests := []func(*testing.T, Version){
		testVerify,
		testVerifyConcurrent,
		testVerifyEmptyKeyring,
		testVerifyDetachedEmptyKeyring,
	}
	runTestsOverVersions(t, "test", tests)
}
