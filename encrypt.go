// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

type encryptStream struct {
	output     io.Writer
	encoder    encoder
	header     *EncryptionHeader
	payloadKey SymmetricKey
	buffer     bytes.Buffer
	inblock    []byte
	headerHash headerHash
	macKeys    []macKey

	numBlocks encryptionBlockNumber // the lower 64 bits of the nonce

	didHeader bool
	eof       bool
	err       error
}

func (es *encryptStream) Write(plaintext []byte) (int, error) {

	if es.err != nil {
		return 0, es.err
	}

	var ret int
	if ret, es.err = es.buffer.Write(plaintext); es.err != nil {
		return 0, es.err
	}
	for es.buffer.Len() >= encryptionBlockSize {
		es.err = es.encryptBlock()
		if es.err != nil {
			return 0, es.err
		}
	}
	return ret, nil
}

func (es *encryptStream) encryptBlock() error {
	var n int
	var err error
	n, err = es.buffer.Read(es.inblock[:])
	if err != nil {
		return err
	}
	return es.encryptBytes(es.inblock[0:n])
}

func (es *encryptStream) encryptBytes(b []byte) error {

	if err := es.numBlocks.check(); err != nil {
		return err
	}

	nonce := nonceForChunkSecretBox(es.numBlocks)
	ciphertext := secretbox.Seal([]byte{}, b, (*[24]byte)(&nonce), (*[32]byte)(&es.payloadKey))

	block := encryptionBlock{
		PayloadCiphertext: ciphertext,
	}

	// Compute the digest to authenticate, and authenticate it for each
	// recipient.
	hashToAuthenticate := computePayloadHash(es.headerHash, nonce, ciphertext)
	for _, macKey := range es.macKeys {
		authenticator := computePayloadAuthenticator(macKey, hashToAuthenticate)
		block.HashAuthenticators = append(block.HashAuthenticators, authenticator)
	}

	if err := es.encoder.Encode(block); err != nil {
		return err
	}

	es.numBlocks++
	return nil
}

// Do some sanity checking on the receivers. Check that receivers
// aren't sent to twice; check that there's at least one receiver.
func (es *encryptStream) checkReceivers(v []BoxPublicKey) error {

	if len(v) == 0 {
		return ErrBadReceivers
	}

	tot := uint64(0)

	// Make sure that each receiver only shows up in the set once.
	receiversAsSet := make(map[string]struct{})

	for _, receiver := range v {
		// Make sure this key hasn't been used before
		kid := receiver.ToKID()
		kidString := hex.EncodeToString(kid)
		if _, found := receiversAsSet[kidString]; found {
			return ErrRepeatedKey(kid)
		}
		receiversAsSet[kidString] = struct{}{}
		tot++
	}

	// Don't allow more than 2^31 receivers.
	if tot >= 0x7fffffff {
		return ErrBadReceivers
	}

	return nil
}

func checkKnownVersion(version Version) error {
	for _, knownVersion := range KnownVersions() {
		if version == knownVersion {
			return nil
		}
	}
	return ErrBadVersion{version}
}

func (es *encryptStream) init(version Version, sender BoxSecretKey, receivers []BoxPublicKey) error {
	if err := checkKnownVersion(version); err != nil {
		return err
	}

	if err := es.checkReceivers(receivers); err != nil {
		return err
	}

	ephemeralKey, err := receivers[0].CreateEphemeralKey()
	if err != nil {
		return err
	}

	// If we have a nil Sender key, then we really want the ephemeral key
	// as the main encryption key.
	if sender == nil {
		sender = ephemeralKey
	}

	eh := &EncryptionHeader{
		FormatName: FormatName,
		Version:    version,
		Type:       MessageTypeEncryption,
		Ephemeral:  ephemeralKey.GetPublicKey().ToKID(),
	}
	es.header = eh
	if err := randomFill(es.payloadKey[:]); err != nil {
		return err
	}

	nonce := nonceForSenderKeySecretBox()
	eh.SenderSecretbox = secretbox.Seal([]byte{}, sender.GetPublicKey().ToKID(), (*[24]byte)(&nonce), (*[32]byte)(&es.payloadKey))

	var order []int
	order, eh.Receivers = boxPayloadKeyForReceivers(version, receivers, ephemeralKey, es.payloadKey)

	// Encode the header to bytes, hash it, then double encode it.
	headerBytes, err := encodeToBytes(es.header)
	if err != nil {
		return err
	}
	es.headerHash = sha512.Sum512(headerBytes)
	err = es.encoder.Encode(headerBytes)
	if err != nil {
		return err
	}

	// TODO: Plumb the pre-computed shared keys above through to
	// computeMACKeysSender.
	es.macKeys = computeMACKeysSender(es.header.Version, order, sender, ephemeralKey, receivers, es.headerHash)

	return nil
}

func computeMACKeySender(version Version, index uint64, secret, eSecret BoxSecretKey, public BoxPublicKey, headerHash headerHash) macKey {
	// Switch on the whole version (i.e., not just the major
	// version) since we're writing.
	switch version {
	case Version1():
		nonce := nonceForMACKeyBoxV1(headerHash)
		return computeMACKeySingle(secret, public, nonce)
	case Version2():
		nonce := nonceForMACKeyBoxV2(headerHash, false, index)
		mac := computeMACKeySingle(secret, public, nonce)
		eNonce := nonceForMACKeyBoxV2(headerHash, true, index)
		eMAC := computeMACKeySingle(eSecret, public, eNonce)
		return sum512Truncate256(append(mac[:], eMAC[:]...))
	default:
		panic(ErrBadVersion{version})
	}
}

func computeMACKeysSender(version Version, order []int, sender, ephemeralKey BoxSecretKey, receivers []BoxPublicKey, headerHash headerHash) []macKey {
	macKeys := make([]macKey, len(receivers))
	// Use the header hash to compute the MAC keys.
	for i, receiver := range receivers {
		index := order[i]
		macKey := computeMACKeySender(version, uint64(index), sender, ephemeralKey, receiver, headerHash)
		macKeys[index] = macKey
	}
	return macKeys
}

// boxPayloadKeyForReceivers returns an order and an array of
// receiverKeys such that the receiverKeys for receivers[i] is in
// receiverKeysArray[order[i]].
func boxPayloadKeyForReceivers(version Version, receivers []BoxPublicKey, ephemeralKey BoxSecretKey, payloadKey SymmetricKey) (order []int, receiverKeysArray []receiverKeys) {
	switch version.Major {
	case 1:
		order = make([]int, len(receivers))
		for i := 0; i < len(receivers); i++ {
			order[i] = i
		}
	case 2:
		order = randomPerm(len(receivers))
	default:
		// Let caller be responsible for filtering out unknown
		// versions.
		panic(ErrBadVersion{version})
	}

	receiverKeysArray = make([]receiverKeys, len(receivers))
	for i, receiver := range receivers {
		index := order[i]
		sharedKey := ephemeralKey.Precompute(receiver)
		nonce := nonceForPayloadKeyBox(version, uint64(index))
		payloadKeyBox := sharedKey.Box(nonce, payloadKey[:])

		keys := receiverKeys{PayloadKeyBox: payloadKeyBox}

		// Don't specify the receivers if this public key wants to hide
		if !receiver.HideIdentity() {
			keys.ReceiverKID = receiver.ToKID()
		}

		receiverKeysArray[index] = keys
	}

	return order, receiverKeysArray
}

func (es *encryptStream) Close() error {
	for es.buffer.Len() > 0 {
		err := es.encryptBlock()
		if err != nil {
			return err
		}
	}
	return es.writeFooter()
}

func (es *encryptStream) writeFooter() error {
	return es.encryptBytes([]byte{})
}

// NewEncryptStream creates a stream that consumes plaintext data.
// It will write out encrypted data to the io.Writer passed in as ciphertext.
// The encryption is from the specified sender, and is encrypted for the
// given receivers.
//
// Returns an io.WriteClose that accepts plaintext data to be encrypted; and
// also returns an error if initialization failed.
func NewEncryptStream(version Version, ciphertext io.Writer, sender BoxSecretKey, receivers []BoxPublicKey) (io.WriteCloser, error) {
	es := &encryptStream{
		output:  ciphertext,
		encoder: newEncoder(ciphertext),
		inblock: make([]byte, encryptionBlockSize),
	}
	err := es.init(version, sender, receivers)
	return es, err
}

// Seal a plaintext from the given sender, for the specified receiver groups.
// Returns a ciphertext, or an error if something bad happened.
func Seal(version Version, plaintext []byte, sender BoxSecretKey, receivers []BoxPublicKey) (out []byte, err error) {
	var buf bytes.Buffer
	es, err := NewEncryptStream(version, &buf, sender, receivers)
	if err != nil {
		return nil, err
	}
	if _, err := es.Write(plaintext); err != nil {
		return nil, err
	}
	if err := es.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
