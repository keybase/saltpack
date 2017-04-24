// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
)

type signAttachedStream struct {
	version    Version
	headerHash headerHash
	encoder    encoder
	buffer     bytes.Buffer
	seqno      packetSeqno
	secretKey  SigningSecretKey
}

func newSignAttachedStream(version Version, w io.Writer, signer SigningSecretKey) (*signAttachedStream, error) {
	if signer == nil {
		return nil, ErrInvalidParameter{message: "no signing key provided"}
	}

	header, err := newSignatureHeader(version, signer.GetPublicKey(), MessageTypeAttachedSignature)
	if err != nil {
		return nil, err
	}

	// Encode the header bytes.
	headerBytes, err := encodeToBytes(header)
	if err != nil {
		return nil, err
	}

	// Compute the header hash.
	headerHash := hashHeader(headerBytes)

	// Create the attached stream object.
	stream := &signAttachedStream{
		version:    version,
		headerHash: headerHash,
		encoder:    newEncoder(w),
		secretKey:  signer,
	}

	// Double encode the header bytes onto the wire.
	err = stream.encoder.Encode(headerBytes)
	if err != nil {
		return nil, err
	}

	return stream, nil
}

func (s *signAttachedStream) Write(p []byte) (int, error) {
	n, err := s.buffer.Write(p)
	if err != nil {
		return 0, err
	}

	// TODO: Change to >.
	for s.buffer.Len() >= signatureBlockSize {
		if err := s.signBlock(false); err != nil {
			return 0, err
		}
	}

	return n, nil
}

func (s *signAttachedStream) Close() error {
	if s.buffer.Len() > 0 {
		if err := s.signBlock(false); err != nil {
			return err
		}
	}

	if s.buffer.Len() > 0 {
		panic(fmt.Sprintf("s.buffer.Len()=%d > 0", s.buffer.Len()))
	}

	return s.signBlock(true)
}

func makeSignatureBlock(version Version, chunk, sig []byte, isFinal bool) interface{} {
	sb := signatureBlock{
		PayloadChunk: chunk,
		Signature:    sig,
	}
	return sb
}

func checkSignBlockRead(version Version, isFinal bool, blockSize, chunkLen, bufLen int) {
	die := func() error {
		return fmt.Errorf("invalid signBlock read state: version=%s, isFinal=%t, chunkLen=%d, bufLen=%d", chunkLen, bufLen)
	}

	// We shouldn't read more than a full block's worth.
	if chunkLen > blockSize {
		die()
	}

	// If we read less than a full block's worth, then we
	// shouldn't have anything left in the buffer.
	if chunkLen < blockSize && bufLen > 0 {
		die()
	}

	switch version {
	case Version1():
		// isFinal must be equivalent to chunkLen being 0
		// (which, by the above, implies that bufLen == 0).
		if isFinal != (chunkLen == 0) {
			die()
		}

	case Version2():
		// If isFinal, then chunkLen can be any number,
		// buf bufLen must be 0.
		if isFinal != (bufLen == 0) {
			die()
		}

	default:
		panic(ErrBadVersion{version})
	}
}

func (s *signAttachedStream) signBlock(isFinal bool) error {
	chunk := s.buffer.Next(signatureBlockSize)
	checkSignBlockRead(s.version, isFinal, signatureBlockSize, len(chunk), s.buffer.Len())

	sig, err := s.computeSig(chunk, s.seqno)
	if err != nil {
		return err
	}

	sBlock := makeSignatureBlock(s.version, chunk, sig, isFinal)
	if err := s.encoder.Encode(sBlock); err != nil {
		return err
	}

	s.seqno++
	return nil
}

func (s *signAttachedStream) computeSig(payloadChunk []byte, seqno packetSeqno) ([]byte, error) {
	return s.secretKey.Sign(attachedSignatureInput(s.headerHash, payloadChunk, seqno))
}

type signDetachedStream struct {
	encoder   encoder
	secretKey SigningSecretKey
	hasher    hash.Hash
}

func newSignDetachedStream(version Version, w io.Writer, signer SigningSecretKey) (*signDetachedStream, error) {
	if signer == nil {
		return nil, ErrInvalidParameter{message: "no signing key provided"}
	}

	header, err := newSignatureHeader(version, signer.GetPublicKey(), MessageTypeDetachedSignature)
	if err != nil {
		return nil, err
	}

	// Encode the header bytes.
	headerBytes, err := encodeToBytes(header)
	if err != nil {
		return nil, err
	}

	// Compute the header hash.
	headerHash := hashHeader(headerBytes)

	// Create the detached stream object.
	stream := &signDetachedStream{
		encoder:   newEncoder(w),
		secretKey: signer,
		hasher:    sha512.New(),
	}

	// Double encode the header bytes onto the wire.
	err = stream.encoder.Encode(headerBytes)
	if err != nil {
		return nil, err
	}

	// Start off the message digest with the header hash. Subsequent calls to
	// Write() will push message bytes into this digest.
	stream.hasher.Write(headerHash[:])

	return stream, nil
}

func (s *signDetachedStream) Write(p []byte) (int, error) {
	return s.hasher.Write(p)
}

func (s *signDetachedStream) Close() error {
	signature, err := s.secretKey.Sign(detachedSignatureInputFromHash(s.hasher.Sum(nil)))
	if err != nil {
		return err
	}

	return s.encoder.Encode(signature)
}
