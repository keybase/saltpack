// Copyright 2018 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"testing"

	"github.com/keybase/go-codec/codec"
	"github.com/stretchr/testify/require"
)

// Test that ints in headers are encoded as positive fixnums.
func TestHeaderHardcoded(t *testing.T) {
	header := EncryptionHeader{
		Version: Version2(),
		Type:    MessageTypeDetachedSignature,
	}

	expectedBytes := []byte{0x96, 0xa0, 0x92, 0x2, 0x0, 0x2, 0xc0, 0xc0, 0xc0}
	bytes, err := encodeToBytes(header)
	require.NoError(t, err)
	require.Equal(t, expectedBytes, bytes)
}

// Test that encryptionBlockV2 encodes and decodes properly.
func TestEncryptionBlockV2RoundTrip(t *testing.T) {
	isFinal := false
	hashAuthenticators := []payloadAuthenticator{{0x1}, {0x2}}
	payloadCiphertext := []byte("TestEncryptionBlockV2RoundTrip")

	blockV2 := encryptionBlockV2{
		encryptionBlockV1: encryptionBlockV1{
			HashAuthenticators: hashAuthenticators,
			PayloadCiphertext:  payloadCiphertext,
		},
		IsFinal: isFinal,
	}

	h := codecHandle()

	var blockV2Bytes1 []byte
	encoder := codec.NewEncoderBytes(&blockV2Bytes1, h)
	blockV2.CodecEncodeSelf(encoder)

	blockV2Bytes2, err := encodeToBytes(blockV2)
	require.NoError(t, err)

	require.Equal(t, blockV2Bytes1, blockV2Bytes2)

	var blockV2Decoded1 encryptionBlockV2
	decoder := codec.NewDecoderBytes(blockV2Bytes1, h)
	blockV2Decoded1.CodecDecodeSelf(decoder)
	require.Equal(t, blockV2, blockV2Decoded1)

	var blockV2Decoded2 encryptionBlockV2
	err = decodeFromBytes(&blockV2Decoded2, blockV2Bytes1)
	require.NoError(t, err)

	require.Equal(t, blockV2, blockV2Decoded2)
}

// Test that the encoded field order for encryptionBlockV2 puts
// IsFinal first.
func TestEncryptionBlockV2FieldOrder(t *testing.T) {
	isFinal := true
	hashAuthenticators := []payloadAuthenticator{{0x3}, {0x4}}
	payloadCiphertext := []byte("TestEncryptionBlockV2FieldOrder")

	blockV2 := encryptionBlockV2{
		encryptionBlockV1: encryptionBlockV1{
			HashAuthenticators: hashAuthenticators,
			PayloadCiphertext:  payloadCiphertext,
		},
		IsFinal: isFinal,
	}

	blockV2Bytes, err := encodeToBytes(blockV2)
	require.NoError(t, err)

	var blockV2Decoded encryptionBlockV2
	err = decodeFromBytes([]interface{}{
		&blockV2Decoded.IsFinal,
		&blockV2Decoded.HashAuthenticators,
		&blockV2Decoded.PayloadCiphertext,
	}, blockV2Bytes)
	require.NoError(t, err)

	require.Equal(t, blockV2, blockV2Decoded)
}

// Test that signatureBlockV2 encodes and decodes properly.
func TestSignatureBlockV2RoundTrip(t *testing.T) {
	isFinal := false
	signature := []byte("TestSignatureBlockV2RoundTrip signature")
	payloadChunk := []byte("TestSignatureBlockV2RoundTrip payload")

	blockV2 := signatureBlockV2{
		signatureBlockV1: signatureBlockV1{
			Signature:    signature,
			PayloadChunk: payloadChunk,
		},
		IsFinal: isFinal,
	}

	h := codecHandle()

	var blockV2Bytes1 []byte
	encoder := codec.NewEncoderBytes(&blockV2Bytes1, h)
	blockV2.CodecEncodeSelf(encoder)

	blockV2Bytes2, err := encodeToBytes(blockV2)
	require.NoError(t, err)

	require.Equal(t, blockV2Bytes1, blockV2Bytes2)

	var blockV2Decoded1 signatureBlockV2
	decoder := codec.NewDecoderBytes(blockV2Bytes1, h)
	blockV2Decoded1.CodecDecodeSelf(decoder)
	require.Equal(t, blockV2, blockV2Decoded1)

	var blockV2Decoded2 signatureBlockV2
	err = decodeFromBytes(&blockV2Decoded2, blockV2Bytes1)
	require.NoError(t, err)

	require.Equal(t, blockV2, blockV2Decoded2)
}

// Test that the encoded field order for signatureBlockV2 puts
// IsFinal first.
func TestSignatureBlockV2FieldOrder(t *testing.T) {
	isFinal := true
	signature := []byte("TestSignatureBlockV2FieldOrder signature")
	payloadChunk := []byte("TestSignatureBlockV2FieldOrder payload")

	blockV2 := signatureBlockV2{
		signatureBlockV1: signatureBlockV1{
			Signature:    signature,
			PayloadChunk: payloadChunk,
		},
		IsFinal: isFinal,
	}

	blockV2Bytes, err := encodeToBytes(blockV2)
	require.NoError(t, err)

	var blockV2Decoded signatureBlockV2
	err = decodeFromBytes([]interface{}{
		&blockV2Decoded.IsFinal,
		&blockV2Decoded.Signature,
		&blockV2Decoded.PayloadChunk,
	}, blockV2Bytes)
	require.NoError(t, err)

	require.Equal(t, blockV2, blockV2Decoded)
}
