// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckSigncryptReceiverCount(t *testing.T) {
	err := checkSigncryptReceiverCount(0, 0)
	require.Equal(t, ErrBadReceivers, err)

	err = checkSigncryptReceiverCount(1, 0)
	require.NoError(t, err)

	err = checkSigncryptReceiverCount(0, 1)
	require.NoError(t, err)

	err = checkSigncryptReceiverCount(-1, 0)
	require.Equal(t, ErrBadReceivers, err)

	err = checkSigncryptReceiverCount(0, -1)
	require.Equal(t, ErrBadReceivers, err)

	err = checkSigncryptReceiverCount(maxReceiverCount, 1)
	require.Equal(t, ErrBadReceivers, err)

	err = checkSigncryptReceiverCount(1, maxReceiverCount)
	require.Equal(t, ErrBadReceivers, err)

	err = checkSigncryptReceiverCount(maxReceiverCount, maxReceiverCount)
	require.Equal(t, ErrBadReceivers, err)
}

func getSigncryptionReceiverOrder(receivers []receiverKeysMaker) []int {
	order := make([]int, len(receivers))
	for i, r := range receivers {
		switch r := r.(type) {
		case receiverBoxKey:
			order[i] = int(r.pk.(boxPublicKey).key[0])
		case ReceiverSymmetricKey:
			order[i] = int(r.Key[0])
		}
	}
	return order
}

func TestShuffleSigncryptionReceivers(t *testing.T) {
	receiverCount := 20

	var receiverBoxKeys []BoxPublicKey
	for i := 0; i < receiverCount/2; i++ {
		k := boxPublicKey{
			key: RawBoxKey{byte(i)},
		}
		receiverBoxKeys = append(receiverBoxKeys, k)
	}

	var receiverSymmetricKeys []ReceiverSymmetricKey
	for i := receiverCount / 2; i < receiverCount; i++ {
		k := ReceiverSymmetricKey{
			Key: SymmetricKey{byte(i)},
		}
		receiverSymmetricKeys = append(receiverSymmetricKeys, k)
	}

	shuffled, err := shuffleSigncryptReceivers(receiverBoxKeys, receiverSymmetricKeys)
	require.NoError(t, err)

	shuffledOrder := getSigncryptionReceiverOrder(shuffled)
	require.True(t, isValidNonTrivialPermutation(receiverCount, shuffledOrder), "shuffledOrder == %+v is an invalid or trivial permutation", shuffledOrder)
}

func TestNewSigncryptSealStreamShuffledReaders(t *testing.T) {
	receiverCount := 20

	// Don't include any BoxPublicKeys as it's hard to go from the
	// identifier to the index.

	var receiverSymmetricKeys []ReceiverSymmetricKey
	for i := 0; i < receiverCount; i++ {
		k := ReceiverSymmetricKey{
			Key:        SymmetricKey{byte(i)},
			Identifier: []byte{byte(i)},
		}
		receiverSymmetricKeys = append(receiverSymmetricKeys, k)
	}

	var ciphertext bytes.Buffer
	_, err := NewSigncryptSealStream(&ciphertext, ephemeralKeyCreator{}, nil, nil, receiverSymmetricKeys)
	require.NoError(t, err)

	var headerBytes []byte
	err = decodeFromBytes(&headerBytes, ciphertext.Bytes())
	require.NoError(t, err)

	var header SigncryptionHeader
	err = decodeFromBytes(&header, headerBytes)
	require.NoError(t, err)

	shuffledOrder := getEncryptReceiverKeysOrder(header.Receivers)
	require.True(t, isValidNonTrivialPermutation(receiverCount, shuffledOrder), "shuffledOrder == %+v is an invalid or trivial permutation", shuffledOrder)
}

// TODO: Add hardcoded signcryption seal/open tests, like
// Test{Seal,Open}HardcodedEncryptMessageV{1,2}.
