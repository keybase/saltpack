// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"github.com/keybase/go-codec/codec"
	"golang.org/x/crypto/poly1305"
)

// encryptionBlockNumber describes which block number we're at in the sequence
// of encrypted blocks. Each encrypted block of course fits into a packet.
type encryptionBlockNumber uint64

func codecHandle() *codec.MsgpackHandle {
	var mh codec.MsgpackHandle
	mh.WriteExt = true
	return &mh
}

func randomFill(b []byte) (err error) {
	l := len(b)
	n, err := rand.Read(b)
	if err != nil {
		return err
	}
	if n != l {
		return ErrInsufficientRandomness
	}
	return nil
}

func (e encryptionBlockNumber) check() error {
	if e >= encryptionBlockNumber(0xffffffffffffffff) {
		return ErrPacketOverflow
	}
	return nil
}

func assertEndOfStream(stream *msgpackStream) error {
	var i interface{}
	_, err := stream.Read(&i)
	if err == nil {
		err = ErrTrailingGarbage
	}
	return err
}

type headerHash [sha512.Size]byte

func attachedSignatureInput(headerHash headerHash, block *signatureBlock) []byte {
	hasher := sha512.New()
	hasher.Write(headerHash[:])
	binary.Write(hasher, binary.BigEndian, block.seqno)
	hasher.Write(block.PayloadChunk)

	var buf bytes.Buffer
	buf.Write([]byte(signatureAttachedString))
	buf.Write(hasher.Sum(nil))

	return buf.Bytes()
}

func detachedSignatureInput(headerHash headerHash, plaintext []byte) []byte {
	hasher := sha512.New()
	hasher.Write(headerHash[:])
	hasher.Write(plaintext)

	return detachedSignatureInputFromHash(hasher.Sum(nil))
}

func detachedSignatureInputFromHash(plaintextAndHeaderHash []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte(signatureDetachedString))
	buf.Write(plaintextAndHeaderHash)

	return buf.Bytes()
}

func copyEqualSize(out, in []byte) {
	if len(out) != len(in) {
		panic(fmt.Sprintf("len(out)=%d != len(in)=%d", len(out), len(in)))
	}
	copy(out, in)
}

func copyEqualSizeStr(out []byte, in string) {
	if len(out) != len(in) {
		panic(fmt.Sprintf("len(out)=%d != len(in)=%d", len(out), len(in)))
	}
	copy(out, in)
}

func sliceToByte24(in []byte) [24]byte {
	var out [24]byte
	copyEqualSize(out[:], in)
	return out
}

func stringToByte24(in string) [24]byte {
	var out [24]byte
	copyEqualSizeStr(out[:], in)
	return out
}

func sliceToByte32(in []byte) [32]byte {
	var out [32]byte
	copyEqualSize(out[:], in)
	return out
}

func sliceToByte64(in []byte) [64]byte {
	var out [64]byte
	copyEqualSize(out[:], in)
	return out
}

type macKey [cryptoAuthKeyBytes]byte

type payloadHash [sha512.Size]byte

type payloadAuthenticator [cryptoAuthBytes]byte

func (pa payloadAuthenticator) Equal(other payloadAuthenticator) bool {
	return hmac.Equal(pa[:], other[:])
}

func computePayloadAuthenticator(macKey macKey, payloadHash payloadHash) payloadAuthenticator {
	// Equivalent to crypto_auth, but using Go's builtin HMAC. Truncates
	// SHA512, instead of calling SHA512/256, which has different IVs.
	authenticatorDigest := hmac.New(sha512.New, macKey[:])
	authenticatorDigest.Write(payloadHash[:])
	fullMAC := authenticatorDigest.Sum(nil)
	return sliceToByte32(fullMAC[:cryptoAuthBytes])
}

func computeMACKeySingle(secret BoxSecretKey, public BoxPublicKey, nonce *Nonce) macKey {
	macKeyBox := secret.Box(public, nonce, make([]byte, cryptoAuthKeyBytes))
	return sliceToByte32(macKeyBox[poly1305.TagSize : poly1305.TagSize+cryptoAuthKeyBytes])
}

func sum512Truncate256(in []byte) [32]byte {
	// Consistent with computePayloadAuthenticator in that it
	// truncates SHA512 instead of calling SHA512/256, which has
	// different IVs.
	sum512 := sha512.Sum512(in)
	var out [32]byte
	copyEqualSize(out[:], sum512[:32])
	return out
}

func computeMACKeySender(version Version, secret, eSecret BoxSecretKey, public BoxPublicKey, headerHash headerHash) macKey {
	switch version {
	case Version1():
		nonce := nonceForMACKeyBoxV1(headerHash)
		return computeMACKeySingle(secret, public, nonce)
	case Version2():
		// TODO: Use v2.
		nonce := nonceForMACKeyBoxV1(headerHash)
		mac1 := computeMACKeySingle(secret, public, nonce)
		mac2 := computeMACKeySingle(eSecret, public, nonce)
		return sum512Truncate256(append(mac1[:], mac2[:]...))
	default:
		panic(ErrBadVersion{version})
	}
}

func computeMACKeyReceiver(version Version, secret BoxSecretKey, public, ePublic BoxPublicKey, headerHash headerHash) macKey {
	switch version {
	case Version1():
		nonce := nonceForMACKeyBoxV1(headerHash)
		return computeMACKeySingle(secret, public, nonce)
	case Version2():
		// TODO: Use v2.
		nonce := nonceForMACKeyBoxV1(headerHash)
		mac1 := computeMACKeySingle(secret, public, nonce)
		mac2 := computeMACKeySingle(secret, ePublic, nonce)
		return sum512Truncate256(append(mac1[:], mac2[:]...))
	default:
		panic(ErrBadVersion{version})
	}
}

func computeMACKeysSender(version Version, sender, ephemeralKey BoxSecretKey, receivers []BoxPublicKey, headerHash headerHash) []macKey {
	var macKeys []macKey
	for _, receiver := range receivers {
		macKey := computeMACKeySender(version, sender, ephemeralKey, receiver, headerHash)
		macKeys = append(macKeys, macKey)
	}
	return macKeys
}

func computePayloadHash(headerHash headerHash, nonce Nonce, payloadCiphertext []byte) payloadHash {
	payloadDigest := sha512.New()
	payloadDigest.Write(headerHash[:])
	payloadDigest.Write(nonce[:])
	payloadDigest.Write(payloadCiphertext)
	h := payloadDigest.Sum(nil)
	return sliceToByte64(h)
}

func hashHeader(headerBytes []byte) headerHash {
	return sha512.Sum512(headerBytes)
}
