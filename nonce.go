package saltpack

import (
	"crypto/rand"
	"encoding/binary"
)

const nonceBytes = 24

// Nonce is a NaCl-style nonce, with 24 bytes of data, some of which can be
// counter values, and some of which can be random-ish values.
type Nonce [nonceBytes]byte

func nonceForSenderKeySecretBox() Nonce {
	return stringToByte24("saltpack_sender_key_sbox")
}

func nonceForPayloadKeyBoxV1() Nonce {
	return stringToByte24("saltpack_payload_key_box")
}

func nonceForPayloadKeyBoxV2(recip uint64) Nonce {
	// TODO: Actually mix in recip.
	return stringToByte24("saltpack_recipsbXXXXXXXX")
}

func nonceForDerivedSharedKey() Nonce {
	return stringToByte24("saltpack_derived_sboxkey")
}

func nonceForMACKeyBoxV1(headerHash headerHash) Nonce {
	return sliceToByte24(headerHash[:nonceBytes])
}

func nonceForMACKeyBoxV2(headerHash headerHash, recip uint64) Nonce {
	var n Nonce
	copyEqualSize(n[:len(n)-8], headerHash[:len(n)-8])
	binary.BigEndian.PutUint64(n[len(n)-8:], uint64(recip))
	return n
}

// Construct the nonce for the ith block of payload.
func nonceForChunkSecretBox(i encryptionBlockNumber) Nonce {
	var n Nonce
	copyEqualSizeStr(n[0:16], "saltpack_ploadsb")
	binary.BigEndian.PutUint64(n[16:], uint64(i))
	return n
}

// Construct the nonce for the ith block of payload. Differs in one letter from
// above. There's almost certainly no harm in using the same nonces here as
// above, since the encryption keys are ephemeral and the signatures already
// have their own context, but at the same time it's a good practice.
func nonceForChunkSigncryption(i encryptionBlockNumber) Nonce {
	var n Nonce
	copyEqualSizeStr(n[0:16], "saltpack_ploadsc")
	binary.BigEndian.PutUint64(n[16:], uint64(i))
	return n
}

// sigNonce is a nonce for signatures.
type sigNonce [16]byte

// newSigNonce creates a sigNonce with random bytes.
func newSigNonce() (sigNonce, error) {
	var n sigNonce
	if _, err := rand.Read(n[:]); err != nil {
		return sigNonce{}, err
	}
	return n, nil
}
