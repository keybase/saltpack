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

func TestDecryptErrorAtEOF(t *testing.T) {
	plaintext := randomMsg(t, 128)
	keyring, receiverBoxKeys := makeKeyringWithOneKey(t)

	senderSigningPrivKey := makeSigningKey(t, keyring)

	sealed, err := SigncryptSeal(plaintext, ephemeralKeyCreator{}, senderSigningPrivKey, receiverBoxKeys, nil)
	require.NoError(t, err)

	var reader io.Reader = bytes.NewReader(sealed)
	errAtEOF := errors.New("err at EOF")
	reader = errAtEOFReader{reader, errAtEOF}
	_, stream, err := NewSigncryptOpenStream(reader, keyring, nil)
	require.NoError(t, err)

	msg, err := io.ReadAll(stream)
	requireErrSuffix(t, err, errAtEOF.Error())

	// Since the bytes are still authenticated, the decrypted
	// message should still compare equal to the original input.
	require.Equal(t, plaintext, msg)
}

func TestDecryptNoKey(t *testing.T) {
	plaintext := randomMsg(t, 128)
	keyring, receiverBoxKeys := makeKeyringWithOneKey(t)
	senderSigningPrivKey := makeSigningKey(t, keyring)

	sealed, err := SigncryptSeal(plaintext, ephemeralKeyCreator{}, senderSigningPrivKey, receiverBoxKeys, nil)
	require.NoError(t, err)

	// Open with empty keyring
	emptyKeyring := makeEmptyKeyring()
	sender, msg, openErr := SigncryptOpen(sealed, emptyKeyring, nil)
	require.Equal(t, openErr, ErrNoDecryptionKey)
	require.Nil(t, sender)
	require.Empty(t, msg)
}

func TestDecryptNoSender(t *testing.T) {
	plaintext := randomMsg(t, 128)

	aliceSigningPrivKey := makeSigningSecretKey(t)

	bobKeyring := makeEmptyKeyring()
	bobBoxKey, createErr := createEphemeralKey(false)
	require.NoError(t, createErr)
	bobKeyring.insert(bobBoxKey)

	sealed, err := SigncryptSeal(plaintext, ephemeralKeyCreator{}, aliceSigningPrivKey, []BoxPublicKey{bobBoxKey.GetPublicKey()}, nil)
	require.NoError(t, err)

	// Open with only (reciever) key in keyring (not sender)
	sender, msg, openErr := SigncryptOpen(sealed, bobKeyring, nil)
	require.Equal(t, openErr, ErrNoSenderKey{Sender: aliceSigningPrivKey.GetPublicKey().ToKID()})
	require.Nil(t, sender)
	require.Empty(t, msg)

	// Add signing key and try open again
	bobKeyring.insertSigningKey(aliceSigningPrivKey)
	sender2, msg2, openErr2 := SigncryptOpen(sealed, bobKeyring, nil)
	require.NoError(t, openErr2)
	require.Equal(t, plaintext, msg2)
	require.Equal(t, sender2.ToKID(), aliceSigningPrivKey.GetPublicKey().ToKID())
}
