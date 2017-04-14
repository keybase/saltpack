// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"testing"
)

func TestNonceForPayloadKeyBoxV2(t *testing.T) {
	nonce1 := nonceForPayloadKeyBoxV2(0)
	nonce2 := nonceForPayloadKeyBoxV2(1)

	if nonce2 == nonce1 {
		t.Errorf("nonce2 == nonce1 == %v unexpectedly", nonce1)
	}
}

func TestNonceForMACKeyBoxV2(t *testing.T) {
	hash1 := headerHash{0x01}
	hash2 := headerHash{0x02}

	nonce1 := nonceForMACKeyBoxV2(hash1, false, 0)
	nonce2 := nonceForMACKeyBoxV2(hash2, false, 0)
	nonce3 := nonceForMACKeyBoxV2(hash1, true, 0)
	nonce4 := nonceForMACKeyBoxV2(hash1, false, 1)

	if nonce2 == nonce1 {
		t.Errorf("nonce2 == nonce1 == %v unexpectedly", nonce1)
	}

	if nonce3 == nonce1 {
		t.Errorf("nonce3 == nonce1 == %v unexpectedly", nonce1)
	}

	if nonce4 == nonce1 {
		t.Errorf("nonce4 == nonce1 == %v unexpectedly", nonce1)
	}
}
