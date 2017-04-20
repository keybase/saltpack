// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"testing"
)

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

	shuffled := shuffleSigncryptionReceivers(receiverBoxKeys, receiverSymmetricKeys)

	shuffledOrder := getSigncryptionReceiverOrder(shuffled)
	if !isValidNonTrivialPermutation(receiverCount, shuffledOrder) {
		t.Fatalf("shuffledOrder == %+v is an invalid or trivial permutation", shuffledOrder)
	}
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

	keyring := makeEmptyKeyring(t)

	var ciphertext bytes.Buffer
	strm, err := NewSigncryptSealStream(&ciphertext, keyring, nil, nil, receiverSymmetricKeys)
	if err != nil {
		t.Fatal(err)
	}

	shuffledOrder := getEncryptReceiverKeysOrder(strm.(*signcryptSealStream).header.Receivers)
	if !isValidNonTrivialPermutation(receiverCount, shuffledOrder) {
		t.Fatalf("shuffledOrder == %+v is an invalid or trivial permutation", shuffledOrder)
	}
}
