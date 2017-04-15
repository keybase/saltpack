// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"reflect"
	"testing"
)

func TestSealEncryptionKeyForReceiversPermuted(t *testing.T) {
	const count = 10
	// TODO: Write comment here.
	receiverBoxKeys := make([]BoxPublicKey, count)
	for i := 0; i < count; i++ {
		receiverBoxKeys[i] = boxPublicKey{key: RawBoxKey{byte(i)}}
	}

	receiverSymmetricKeys := make([]ReceiverSymmetricKey, count)
	for i := 0; i < count; i++ {
		receiverSymmetricKeys[i] = ReceiverSymmetricKey{Key: SymmetricKey{byte(i)}}
	}

	ephemeralKey := boxSecretKey{key: RawBoxKey{0x08}}
	encryptionKey := SymmetricKey{0x6}

	receiverKeysArray1 := sealEncryptionKeyForReceivers(receiverBoxKeys, receiverSymmetricKeys, ephemeralKey, encryptionKey)
	receiverKeysArray2 := sealEncryptionKeyForReceivers(receiverBoxKeys, receiverSymmetricKeys, ephemeralKey, encryptionKey)

	// Technically this check is flaky, but the flake probability
	// is 1/20! ~ 2^{-61}.
	if reflect.DeepEqual(receiverKeysArray1, receiverKeysArray2) {
		t.Fatal("Two calls to boxPayloadKeyForReceivers(Version2()) unexpectedly produced the same array")
	}
}
