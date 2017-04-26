// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	mathrand "math/rand"

	"github.com/keybase/go-codec/codec"
	"golang.org/x/crypto/nacl/secretbox"
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
	n, err := cryptorand.Read(b)
	if err != nil {
		return err
	}
	if n != l {
		return ErrInsufficientRandomness
	}
	return nil
}

type cryptoSource struct{}

var _ mathrand.Source = cryptoSource{}

// No need to implement Source64, since mathrand.Rand.Perm() doesn't use it.

func (s cryptoSource) Int63() int64 {
	var buf [8]byte
	cryptorand.Read(buf[:])
	return int64(binary.BigEndian.Uint64(buf[:]) >> 1)
}

func (s cryptoSource) Seed(seed int64) {
	panic("cryptoSource.Seed() called unexpectedly")
}

func randomPerm(n int) []int {
	rnd := mathrand.New(cryptoSource{})
	return rnd.Perm(n)
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

func attachedSignatureInput(version Version, headerHash headerHash, payloadChunk []byte, seqno packetSeqno, isFinal bool) []byte {
	hasher := sha512.New()
	hasher.Write(headerHash[:])
	binary.Write(hasher, binary.BigEndian, seqno)
	switch version.Major {
	case 1:
	// Nothing to do.
	case 2:
		var isFinalByte byte
		if isFinal {
			isFinalByte = 1
		}
		hasher.Write([]byte{isFinalByte})
	default:
		panic(ErrBadVersion{version})
	}
	hasher.Write(payloadChunk)

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

func computeMACKeySingle(secret BoxSecretKey, public BoxPublicKey, nonce Nonce) macKey {
	macKeyBox := secret.Box(public, nonce, make([]byte, cryptoAuthKeyBytes))
	return sliceToByte32(macKeyBox[poly1305.TagSize : poly1305.TagSize+cryptoAuthKeyBytes])
}

func sum512Truncate256(in []byte) [32]byte {
	// Consistent with computePayloadAuthenticator in that it
	// truncates SHA512 instead of calling SHA512/256, which has
	// different IVs.
	sum512 := sha512.Sum512(in)
	return sliceToByte32(sum512[:32])
}

// checkCiphertextState sanity-checks some ciphertext parameters. When
// called by the encryptor, a non-nil error should cause a panic, but
// when called by the decryptor, it should be treated as a regular
// error.
func checkCiphertextState(version Version, ciphertext []byte, isFinal bool) error {
	makeErr := func() error {
		return fmt.Errorf("invalid ciphertext state: version=%s, len(ciphertext)=%d, isFinal=%t", version, len(ciphertext), isFinal)
	}

	if len(ciphertext) < secretbox.Overhead {
		return makeErr()
	}

	switch version.Major {
	case 1:
		if (len(ciphertext) == secretbox.Overhead) != isFinal {
			return makeErr()
		}

	case 2:
		// With V2, it's valid to have a final packet with
		// non-empty plaintext, so the below is the only
		// remaining invalid state.
		//
		// TODO: Ideally, we'd disallow empty packets even
		// with isFinal set, but we still want to allow
		// encrypting an empty message. Plumb through an
		// isFirst flag and change "!isFinal" to "!isFirst ||
		// !isFinal".
		if (len(ciphertext) == secretbox.Overhead) && !isFinal {
			return makeErr()
		}

	default:
		panic(ErrBadVersion{version})
	}

	return nil
}

func computePayloadHash(version Version, headerHash headerHash, nonce Nonce, ciphertext []byte, isFinal bool) payloadHash {
	payloadDigest := sha512.New()
	payloadDigest.Write(headerHash[:])
	payloadDigest.Write(nonce[:])
	switch version.Major {
	case 1:
	// Nothing to do.
	case 2:
		var isFinalByte byte
		if isFinal {
			isFinalByte = 1
		}
		payloadDigest.Write([]byte{isFinalByte})
	default:
		panic(ErrBadVersion{version})
	}
	payloadDigest.Write(ciphertext)
	h := payloadDigest.Sum(nil)
	return sliceToByte64(h)
}

// computeSigncryptionSignatureInput computes the data to be signed in
// signcryption mode.
//
// NOTE: we rely on the nonce containing both the headerHash and the
// isFinal flag.
func computeSigncryptionSignatureInput(nonce Nonce, chunkPlaintext []byte) []byte {
	signatureInput := []byte(signatureEncryptedString)
	signatureInput = append(signatureInput, nonce[:]...)
	plaintextHash := sha512.Sum512(chunkPlaintext)
	signatureInput = append(signatureInput, plaintextHash[:]...)
	return signatureInput
}

func hashHeader(headerBytes []byte) headerHash {
	return sha512.Sum512(headerBytes)
}

// VersionValidator is a function that takes a version and returns nil
// if it's a valid version, and an error otherwise.
type VersionValidator func(version Version) error

// CheckKnownMajorVersion returns nil if the given version has a known
// major version. You probably want to use this with NewDecryptStream,
// unless you want to restrict to specific versions only.
func CheckKnownMajorVersion(version Version) error {
	for _, knownVersion := range KnownVersions() {
		if version.Major == knownVersion.Major {
			return nil
		}
	}
	return ErrBadVersion{version}
}

// SingleVersionValidator returns a VersionValidator that returns nil
// if its given version is equal to desiredVersion.
func SingleVersionValidator(desiredVersion Version) VersionValidator {
	return func(version Version) error {
		if version == desiredVersion {
			return nil
		}

		return ErrBadVersion{version}
	}
}

// checkSignatureState sanity-checks some signature parameters. When
// called by the signer, a non-nil error should cause a panic, but
// when called by the verifier, it should be treated as a regular
// error.
func checkSignatureState(version Version, chunk []byte, isFinal bool) error {
	makeErr := func() error {
		return fmt.Errorf("invalid signature state: version=%s, len(chunk)=%d, isFinal=%t", version, len(chunk), isFinal)
	}

	switch version.Major {
	case 1:
		if (len(chunk) == 0) != isFinal {
			return makeErr()
		}

	case 2:
		// With V2, it's valid to have a final packet with
		// non-empty chunk, so the below is the only remaining
		// invalid state.
		//
		// TODO: Ideally, we'd disallow empty packets even
		// with isFinal set, but we still want to allow
		// signing an empty message. Plumb through an isFirst
		// flag and change "!isFinal" to "!isFirst ||
		// !isFinal".
		if (len(chunk) == 0) && !isFinal {
			return makeErr()
		}

	default:
		panic(ErrBadVersion{version})
	}

	return nil
}
