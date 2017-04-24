package basic

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/keybase/saltpack"
)

func randomMsg(t *testing.T, sz int) []byte {
	out := make([]byte, sz)
	if _, err := rand.Read(out); err != nil {
		t.Fatal(err)
	}
	return out
}

func testBasicBox(t *testing.T, version saltpack.Version) {
	kr := NewKeyring()
	k1, err := kr.GenerateBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := kr.GenerateBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := randomMsg(t, 1024)
	text, err := saltpack.EncryptArmor62Seal(version, msg, k1, []saltpack.BoxPublicKey{k2.GetPublicKey()}, "")
	if err != nil {
		t.Fatal(err)
	}
	_, msg2, _, err := saltpack.Dearmor62DecryptOpen(saltpack.SingleVersionValidator(version), text, kr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, msg2) {
		t.Fatal("failed to recover message")
	}
}

func TestBasicBox(t *testing.T) {
	for _, version := range saltpack.KnownVersions() {
		version := version // capture range variable.
		t.Run(version.String(), func(t *testing.T) {
			testBasicBox(t, version)
		})
	}
}

func TestBasicSign(t *testing.T) {
	kr := NewKeyring()
	k1, err := kr.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := randomMsg(t, 1024)
	sig, err := saltpack.SignArmor62(saltpack.Version1(), msg, k1, "")
	if err != nil {
		t.Fatal(err)
	}
	pk, msg2, _, err := saltpack.Dearmor62Verify(sig, kr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, msg2) {
		t.Fatal("msg payload mismatch")
	}
	if !saltpack.PublicKeyEqual(k1.GetPublicKey(), pk) {
		t.Fatal("public signing key wasn't right")
	}
}
