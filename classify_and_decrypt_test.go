// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsSaltpackBinarySlice(t *testing.T) {
	// Signcryption
	msg := []byte("hello world")
	keyring, receiverBoxKeys := makeKeyringWithOneKey(t)
	senderSigningPrivKey := makeSigningKey(t, keyring)
	sealed, err := SigncryptSeal(msg, ephemeralKeyCreator{}, senderSigningPrivKey, receiverBoxKeys, nil)
	require.NoError(t, err)

	typ, ver, err := IsSaltpackBinarySlice(sealed)
	require.NoError(t, err)
	require.Equal(t, MessageTypeSigncryption, typ)
	require.Equal(t, Version2(), ver)

	// Encryption
	sender := boxSecretKey{
		key: RawBoxKey{0x08},
	}
	receivers := []BoxPublicKey{boxPublicKey{key: RawBoxKey{0x1}}}
	ciphertext, err := Seal(Version2(), msg, sender, receivers)
	require.NoError(t, err)

	typ, ver, err = IsSaltpackBinarySlice(ciphertext)
	require.NoError(t, err)
	require.Equal(t, MessageTypeEncryption, typ)
	require.Equal(t, Version2(), ver)

	// Attached Sig
	key := newSigPrivKey(t)
	asig, err := Sign(Version2(), msg, key)
	require.NoError(t, err)

	typ, ver, err = IsSaltpackBinarySlice(asig)
	require.NoError(t, err)
	require.Equal(t, MessageTypeAttachedSignature, typ)
	require.Equal(t, Version2(), ver)

	// Detached Sig
	dsig, err := SignDetached(Version2(), msg, key)
	require.NoError(t, err)

	typ, ver, err = IsSaltpackBinarySlice(dsig)
	require.NoError(t, err)
	require.Equal(t, MessageTypeDetachedSignature, typ)
	require.Equal(t, Version2(), ver)

	// short message
	typ, ver, err = IsSaltpackBinarySlice(dsig[0:5])
	require.Equal(t, err, ErrShortSliceOrBuffer)
	require.Equal(t, MessageTypeUnknown, typ)
	require.Equal(t, Version{}, ver)

	// invalid messages
	invalid := append([]byte{}, dsig...)
	invalid[0] = 0xff
	typ, ver, err = IsSaltpackBinarySlice(invalid)
	require.Equal(t, ErrNotASaltpackMessage, err)
	require.Equal(t, MessageTypeUnknown, typ)
	require.Equal(t, Version{}, ver)
}

func TestIsSaltpackBinary(t *testing.T) {
	// Signcryption
	msg := []byte("hello world")
	keyring, receiverBoxKeys := makeKeyringWithOneKey(t)
	senderSigningPrivKey := makeSigningKey(t, keyring)
	sealed, err := SigncryptSeal(msg, ephemeralKeyCreator{}, senderSigningPrivKey, receiverBoxKeys, nil)
	require.NoError(t, err)

	typ, ver, err := IsSaltpackBinary(bufio.NewReader(bytes.NewReader(sealed)))
	require.NoError(t, err)
	require.Equal(t, MessageTypeSigncryption, typ)
	require.Equal(t, Version2(), ver)

	// Encryption
	sender := boxSecretKey{
		key: RawBoxKey{0x08},
	}
	receivers := []BoxPublicKey{boxPublicKey{key: RawBoxKey{0x1}}}
	ciphertext, err := Seal(Version2(), msg, sender, receivers)
	require.NoError(t, err)

	typ, ver, err = IsSaltpackBinary(bufio.NewReader(bytes.NewReader(ciphertext)))
	require.NoError(t, err)
	require.Equal(t, MessageTypeEncryption, typ)
	require.Equal(t, Version2(), ver)

	// Attached Sig
	key := newSigPrivKey(t)
	asig, err := Sign(Version2(), msg, key)
	require.NoError(t, err)

	typ, ver, err = IsSaltpackBinary(bufio.NewReader(bytes.NewReader(asig)))
	require.NoError(t, err)
	require.Equal(t, MessageTypeAttachedSignature, typ)
	require.Equal(t, Version2(), ver)

	// Detached Sig
	dsig, err := SignDetached(Version2(), msg, key)
	require.NoError(t, err)

	typ, ver, err = IsSaltpackBinary(bufio.NewReader(bytes.NewReader(dsig)))
	require.NoError(t, err)
	require.Equal(t, MessageTypeDetachedSignature, typ)
	require.Equal(t, Version2(), ver)

	// short message
	typ, ver, err = IsSaltpackBinary(bufio.NewReaderSize(bytes.NewReader(dsig), 5))
	require.Equal(t, ErrShortSliceOrBuffer, err)
	require.Equal(t, MessageTypeUnknown, typ)
	require.Equal(t, Version{}, ver)

	// invalid messages
	invalid := append([]byte{}, dsig...)
	invalid[0] = 0xff
	typ, ver, err = IsSaltpackBinary(bufio.NewReader(bytes.NewReader(invalid)))
	require.Equal(t, ErrNotASaltpackMessage, err)
	require.Equal(t, MessageTypeUnknown, typ)
	require.Equal(t, Version{}, ver)
}

func TestIsSaltpackArmored(t *testing.T) {
	// Signcryption
	msg := []byte("hello world")
	keyring, receiverBoxKeys := makeKeyringWithOneKey(t)
	senderSigningPrivKey := makeSigningKey(t, keyring)

	sealedStr, err := SigncryptArmor62Seal(msg, ephemeralKeyCreator{}, senderSigningPrivKey, receiverBoxKeys, nil, ourBrand)
	require.NoError(t, err)

	brand, typ, ver, err := IsSaltpackArmored(bufio.NewReader(bytes.NewReader([]byte(sealedStr))))
	require.NoError(t, err)
	require.Equal(t, ourBrand, brand)
	require.Equal(t, MessageTypeSigncryption, typ)
	require.Equal(t, Version2(), ver)

	// Encryption
	sender := boxSecretKey{
		key: RawBoxKey{0x08},
	}
	receivers := []BoxPublicKey{boxPublicKey{key: RawBoxKey{0x1}}}

	ciphertextStr, err := EncryptArmor62Seal(Version2(), msg, sender, receivers, ourBrand)
	require.NoError(t, err)

	brand, typ, ver, err = IsSaltpackArmored(bufio.NewReader(bytes.NewReader([]byte(ciphertextStr))))
	require.NoError(t, err)
	require.Equal(t, ourBrand, brand)
	require.Equal(t, MessageTypeEncryption, typ)
	require.Equal(t, Version2(), ver)

	// Attached Sig
	key := newSigPrivKey(t)
	asigStr, err := SignArmor62(Version2(), msg, key, ourBrand)
	require.NoError(t, err)

	brand, typ, ver, err = IsSaltpackArmored(bufio.NewReader(strings.NewReader(asigStr)))
	require.NoError(t, err)
	require.Equal(t, ourBrand, brand)
	require.Equal(t, MessageTypeAttachedSignature, typ)
	require.Equal(t, Version2(), ver)

	// Detached Sig
	dsigStr, err := SignDetachedArmor62(Version2(), msg, key, ourBrand)
	require.NoError(t, err)

	brand, typ, ver, err = IsSaltpackArmored(bufio.NewReader(strings.NewReader(dsigStr)))
	require.NoError(t, err)
	require.Equal(t, ourBrand, brand)
	require.Equal(t, MessageTypeDetachedSignature, typ)
	require.Equal(t, Version2(), ver)

	// short message
	brand, typ, ver, err = IsSaltpackArmored(bufio.NewReaderSize(strings.NewReader(dsigStr), 5))
	require.Equal(t, ErrShortSliceOrBuffer, err)
	require.Equal(t, "", brand)
	require.Equal(t, MessageTypeUnknown, typ)
	require.Equal(t, Version{}, ver)

	// invalid messages
	invalid := append([]byte{}, []byte(dsigStr)...)
	invalid[0] = 0xff
	brand, typ, ver, err = IsSaltpackArmored(bufio.NewReader(bytes.NewReader(invalid)))
	require.Equal(t, err, ErrNotASaltpackMessage)
	require.Equal(t, "", brand)
	require.Equal(t, MessageTypeUnknown, typ)
	require.Equal(t, Version{}, ver)
}

func TestIsSaltpackArmoredShortArmor(t *testing.T) {
	// Signcryption
	msg := []byte("hello world hello world hello world hello world hello world hello world hello world")
	keyring, receiverBoxKeys := makeKeyringWithOneKey(t)
	senderSigningPrivKey := makeSigningKey(t, keyring)

	sealedStr, err := SigncryptArmor62Seal(msg, ephemeralKeyCreator{}, senderSigningPrivKey, receiverBoxKeys, nil, ourBrand)
	require.NoError(t, err)

	// The number 83 directly depends on the length of the header frame, the number of spaces, and the base62 block length
	// for this specific message.
	for i := 0; i < 83; i++ {
		_, _, _, err := IsSaltpackArmoredPrefix(sealedStr[:i])
		require.Equalf(t, ErrShortSliceOrBuffer, err, "Expected ErrShortSliceOrBuffer for i=%v, instead got: %T, %v", i, err, err)
	}
	for i := 84; i < len(sealedStr); i++ {
		_, _, _, err := IsSaltpackArmoredPrefix(sealedStr[:i])
		require.NoErrorf(t, err, "Unexpected error for i = %v: %T, %v", i, err, err)
	}
}

func TestClassifyStream(t *testing.T) {
	// Signcryption
	msg := []byte("hello world")
	keyring, receiverBoxKeys := makeKeyringWithOneKey(t)
	senderSigningPrivKey := makeSigningKey(t, keyring)
	sealed, err := SigncryptSeal(msg, ephemeralKeyCreator{}, senderSigningPrivKey, receiverBoxKeys, nil)
	require.NoError(t, err)

	armored, brand, typ, ver, err := ClassifyStream(bufio.NewReader(bytes.NewReader(sealed)))
	require.NoError(t, err)
	require.False(t, armored)
	require.Equal(t, "", brand)
	require.Equal(t, MessageTypeSigncryption, typ)
	require.Equal(t, Version2(), ver)

	sealedStr, err := SigncryptArmor62Seal(msg, ephemeralKeyCreator{}, senderSigningPrivKey, receiverBoxKeys, nil, ourBrand)
	require.NoError(t, err)

	armored, brand, typ, ver, err = ClassifyStream(bufio.NewReader(bytes.NewReader([]byte(sealedStr))))
	require.NoError(t, err)
	require.True(t, armored)
	require.Equal(t, ourBrand, brand)
	require.Equal(t, MessageTypeSigncryption, typ)
	require.Equal(t, Version2(), ver)

	// Encryption
	sender := boxSecretKey{
		key: RawBoxKey{0x08},
	}
	receivers := []BoxPublicKey{boxPublicKey{key: RawBoxKey{0x1}}}
	ciphertext, err := Seal(Version2(), msg, sender, receivers)
	require.NoError(t, err)

	armored, brand, typ, ver, err = ClassifyStream(bufio.NewReader(bytes.NewReader(ciphertext)))
	require.NoError(t, err)
	require.False(t, armored)
	require.Equal(t, "", brand)
	require.Equal(t, MessageTypeEncryption, typ)
	require.Equal(t, Version2(), ver)

	ciphertextStr, err := EncryptArmor62Seal(Version2(), msg, sender, receivers, ourBrand)
	require.NoError(t, err)

	armored, brand, typ, ver, err = ClassifyStream(bufio.NewReader(bytes.NewReader([]byte(ciphertextStr))))
	require.NoError(t, err)
	require.True(t, armored)
	require.Equal(t, ourBrand, brand)
	require.Equal(t, MessageTypeEncryption, typ)
	require.Equal(t, Version2(), ver)

	// Attached Sig
	key := newSigPrivKey(t)
	asig, err := Sign(Version2(), msg, key)
	require.NoError(t, err)

	armored, brand, typ, ver, err = ClassifyStream(bufio.NewReader(bytes.NewReader(asig)))
	require.NoError(t, err)
	require.False(t, armored)
	require.Equal(t, "", brand)
	require.Equal(t, MessageTypeAttachedSignature, typ)
	require.Equal(t, Version2(), ver)

	asigStr, err := SignArmor62(Version2(), msg, key, ourBrand)
	require.NoError(t, err)

	armored, brand, typ, ver, err = ClassifyStream(bufio.NewReader(strings.NewReader(asigStr)))
	require.NoError(t, err)
	require.True(t, armored)
	require.Equal(t, ourBrand, brand)
	require.Equal(t, MessageTypeAttachedSignature, typ)
	require.Equal(t, Version2(), ver)

	// Detached Sig
	dsig, err := SignDetached(Version2(), msg, key)
	require.NoError(t, err)

	armored, brand, typ, ver, err = ClassifyStream(bufio.NewReader(bytes.NewReader(dsig)))
	require.NoError(t, err)
	require.False(t, armored)
	require.Equal(t, "", brand)
	require.Equal(t, MessageTypeDetachedSignature, typ)
	require.Equal(t, Version2(), ver)

	dsigStr, err := SignDetachedArmor62(Version2(), msg, key, ourBrand)
	require.NoError(t, err)

	armored, brand, typ, ver, err = ClassifyStream(bufio.NewReader(strings.NewReader(dsigStr)))
	require.NoError(t, err)
	require.True(t, armored)
	require.Equal(t, ourBrand, brand)
	require.Equal(t, MessageTypeDetachedSignature, typ)
	require.Equal(t, Version2(), ver)

	// short message
	armored, brand, typ, ver, err = ClassifyStream(bufio.NewReaderSize(bytes.NewReader(dsig), 5))
	require.Equal(t, ErrShortSliceOrBuffer, err)
	require.False(t, armored)
	require.Equal(t, "", brand)
	require.Equal(t, MessageTypeUnknown, typ)
	require.Equal(t, Version{}, ver)

	// invalid messages
	invalid := append([]byte{}, dsig...)
	invalid[0] = 0xff
	armored, brand, typ, ver, err = ClassifyStream(bufio.NewReader(bytes.NewReader(invalid)))
	require.Equal(t, err, ErrNotASaltpackMessage)
	require.False(t, armored)
	require.Equal(t, "", brand)
	require.Equal(t, MessageTypeUnknown, typ)
	require.Equal(t, Version{}, ver)
}

func TestClassifyEncryptedStreamAndMakeDecoder(t *testing.T) {
	// Signcryption
	msg := []byte("hello world")
	keyring, receiverBoxKeys := makeKeyringWithOneKey(t)
	senderSigningPrivKey := makeSigningKey(t, keyring)
	sealed, err := SigncryptSeal(msg, ephemeralKeyCreator{}, senderSigningPrivKey, receiverBoxKeys, nil)
	require.NoError(t, err)

	plainSource, msgType, mki, senderPublic, isArmored, brand, ver, err := ClassifyEncryptedStreamAndMakeDecoder(bytes.NewReader(sealed), keyring, nil)
	require.NoError(t, err)
	plainString, err := io.ReadAll(plainSource)
	require.NoError(t, err)
	require.Equal(t, msg, plainString)
	require.Equal(t, MessageTypeSigncryption, msgType)
	require.Nil(t, mki)
	require.Equal(t, senderSigningPrivKey.GetPublicKey(), senderPublic)
	require.False(t, isArmored)
	require.Equal(t, brand, "")
	require.Equal(t, Version2(), ver)

	sealedStr, err := SigncryptArmor62Seal(msg, ephemeralKeyCreator{}, senderSigningPrivKey, receiverBoxKeys, nil, ourBrand)
	require.NoError(t, err)

	plainSource, msgType, mki, senderPublic, isArmored, brand, ver, err = ClassifyEncryptedStreamAndMakeDecoder(bytes.NewReader([]byte(sealedStr)), keyring, nil)
	require.NoError(t, err)
	plainString, err = io.ReadAll(plainSource)
	require.NoError(t, err)
	require.Equal(t, msg, plainString)
	require.Equal(t, MessageTypeSigncryption, msgType)
	require.Nil(t, mki)
	require.Equal(t, senderSigningPrivKey.GetPublicKey(), senderPublic)
	require.True(t, isArmored)
	require.Equal(t, brand, ourBrand)
	require.Equal(t, Version2(), ver)

	// Encryption
	sender := newBoxKey(t)
	ciphertext, err := Seal(Version2(), msg, sender, receiverBoxKeys)
	require.NoError(t, err)

	plainSource, msgType, mki, senderPublic, isArmored, brand, ver, err = ClassifyEncryptedStreamAndMakeDecoder(bytes.NewReader(ciphertext), keyring, nil)
	require.NoError(t, err)
	plainString, err = io.ReadAll(plainSource)
	require.NoError(t, err)
	require.Equal(t, msg, plainString)
	require.Equal(t, MessageTypeEncryption, msgType)
	require.NoError(t, err)
	require.False(t, mki.SenderIsAnon)
	require.False(t, mki.ReceiverIsAnon)
	require.True(t, PublicKeyEqual(sender.GetPublicKey(), mki.SenderKey))
	require.True(t, PublicKeyEqual(receiverBoxKeys[0], mki.ReceiverKey.GetPublicKey()))
	require.Nil(t, senderPublic)
	require.False(t, isArmored)
	require.Equal(t, brand, "")
	require.Equal(t, Version2(), ver)

	ciphertextStr, err := EncryptArmor62Seal(Version2(), msg, sender, receiverBoxKeys, ourBrand)
	require.NoError(t, err)

	plainSource, msgType, mki, senderPublic, isArmored, brand, ver, err = ClassifyEncryptedStreamAndMakeDecoder(strings.NewReader(ciphertextStr), keyring, nil)
	require.NoError(t, err)
	plainString, err = io.ReadAll(plainSource)
	require.NoError(t, err)
	require.Equal(t, msg, plainString)
	require.Equal(t, MessageTypeEncryption, msgType)
	require.NoError(t, err)
	require.False(t, mki.SenderIsAnon)
	require.False(t, mki.ReceiverIsAnon)
	require.True(t, PublicKeyEqual(sender.GetPublicKey(), mki.SenderKey))
	require.True(t, PublicKeyEqual(receiverBoxKeys[0], mki.ReceiverKey.GetPublicKey()))
	require.Nil(t, senderPublic)
	require.True(t, isArmored)
	require.Equal(t, brand, ourBrand)
	require.Equal(t, Version2(), ver)

	// short message
	_, _, _, _, _, _, _, err = ClassifyEncryptedStreamAndMakeDecoder(strings.NewReader(ciphertextStr[:20]), keyring, nil)
	require.Error(t, err)
	require.Equal(t, ErrShortSliceOrBuffer, err)

	// invalid messages
	invalid := append([]byte{}, ciphertext...)
	invalid[0] = 0xff
	_, _, _, _, _, _, _, err = ClassifyEncryptedStreamAndMakeDecoder(bytes.NewReader(invalid), keyring, nil)
	require.Error(t, err)
	require.Equal(t, ErrNotASaltpackMessage, err)
}
