// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecryptVersionValidator(t *testing.T) {
	plaintext := []byte{0x01}
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	ciphertext, err := Seal(Version1(), plaintext, sender, receivers)
	require.NoError(t, err)

	_, _, err = Open(SingleVersionValidator(Version2()), ciphertext, kr)
	expectedErr := ErrBadVersion{Version1()}
	require.Equal(t, expectedErr, err)
}

func testDecryptNewMinorVersion(t *testing.T, version Version) {
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
	require.NoError(t, err)

	_, _, err = Open(SingleVersionValidator(newVersion), ciphertext, kr)
	require.NoError(t, err)
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
	require.NoError(t, err)

	var reader io.Reader = bytes.NewReader(ciphertext)
	errAtEOF := errors.New("err at EOF")
	reader = errAtEOFReader{reader, errAtEOF}
	_, stream, err := NewDecryptStream(SingleVersionValidator(version), reader, kr)
	require.NoError(t, err)

	msg, err := io.ReadAll(stream)
	requireErrSuffix(t, err, errAtEOF.Error())

	// Since the bytes are still authenticated, the decrypted
	// message should still compare equal to the original input.
	require.Equal(t, plaintext, msg)
}

func TestDecrypt(t *testing.T) {
	tests := []func(*testing.T, Version){
		testDecryptNewMinorVersion,
		testDecryptErrorAtEOF,
	}
	runTestsOverVersions(t, "testDecrypt", tests)
}

const hardcodedV1EncryptedMessage = `
BEGIN KEYBASE SALTPACK ENCRYPTED MESSAGE. kiPgBwdlv6bV9N8 dSkCbjKrku5ZO7I
sQfGHBd7ZxroT7P 1oooGf4WjNkflSq ujGii7s89UFEybr MCxPEHJ7oOvWtnu Hos4mnLWEggEbcO
1799w2eUijCv0AO E4GK7kPKPSFiF5m enAE17GVaRn34Vv wlwxB9LgFzNfg4m D03qjZnVIeBstvT
TGBDN7BnaSiUjW4 Ao0VbJmjuwI2gqt BqTefCIubT0ZvxO zFN8PAoclVLLbWf pPgjOB7eVp3Bbnq
6nhA8Ql55rMNEx8 9XOTpJh4yJBzA5E rpiLelEIo0LfHMA 4WEI2Lk1FXF3txw LPSWpzStekiIImR
tY2Uhf7hcRZFs1P yRr4WYFoWpjotGA 2k6S0L8QHGPbsGl jJKz5m1at0o8XxA MrWrtBnOmkK1kgS
TNm9UX5DiaVxyJ8 4JKgJVTt8JxMacq 37vn4jogmZJr45r gNSrakw8sFv8CaD xMNXqUWkhQ9U8ZI
N1ePua5gTPaECSD ZonBMFRUDpHBFHQ z7hhFmOww4qkUXm xQdpNDg9Ex7YvRT 0CPvP9FsEelrNFH
4xiDSnDAYMguoC6 yC5YmGrYxusmfWC 7CAMYK0lQuuIucF aZCvYRTGRjDj0BA 8vvlXPHcjkyE956
RPY6fYiwVBf2dZg 8lRgd4NjOHdz6v9 6vt3nHGx4ZiUUNT 70xwTjNVIVbH5kV UTI0igySEhyh49z
X5rcwPdcuA2zO4d nyrYEqrAT55ZPsp stRGwbHgQRm36wD c06Z4xYUJv5AtUr R02MT9AqytNeLvu
KvYolx5Wlm95FtR k6EaQ0hfC4oS1nF 6qRgICgl4JaSLBi baciijBMud23IJg aOHE9dR9ZnGJsLm
tgDdKRzle5KLksB sSZiiGKf5uAFr9A Tx9JhFZv3B9GP5v 2s3U289T97Y0hhS UEcuMcyDSbyOLko
dSbguBO4iKLGL6A T1lPhaCzg4n4vZv wW3qEKEflxsRu8O GoS5bg3586PGYP6 UlTCS6uZDZDvZpa
FuHsCazBwbC8RMw mK04rfrmwew. END KEYBASE SALTPACK ENCRYPTED MESSAGE.
`
const hardcodedV1DecryptionKey = "1fcf32dbefa43c1af55f1387b5e30117657a6eb9ef1bbbd4e95b3f1436fc3310"

func requireDearmor62DecryptOpenTo(t *testing.T, expectedPlaintext string, version Version, secretKeyString secretKeyString, armoredCiphertext string) {
	key, err := secretKeyString.toSecretKey()
	require.NoError(t, err)
	keyring := newKeyring()
	keyring.insert(key)
	_, plaintext, _, err := Dearmor62DecryptOpen(SingleVersionValidator(version), armoredCiphertext, keyring)
	require.NoError(t, err)
	require.Equal(t, expectedPlaintext, string(plaintext))
}

func TestHardcodedEncryptedMessageV1(t *testing.T) {
	requireDearmor62DecryptOpenTo(t, "test message!", Version1(), hardcodedV1DecryptionKey, hardcodedV1EncryptedMessage)
}

func testEncryptArmor62SealResultOpen(t *testing.T, result encryptArmor62SealResult) {
	for _, receiver := range result.receivers {
		requireDearmor62DecryptOpenTo(t, result.plaintext, result.version, receiver, result.armoredCiphertext)
	}
}

func TestOpenHardcodedEncryptMessageV1(t *testing.T) {
	testEncryptArmor62SealResultOpen(t, v1EncryptArmor62SealResult)
}

func TestOpenHardcodedEncryptMessageV2(t *testing.T) {
	testEncryptArmor62SealResultOpen(t, v2EncryptArmor62SealResult)
}
