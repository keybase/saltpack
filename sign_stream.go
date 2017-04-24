// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"crypto/sha512"
	"hash"
	"io"
)

type signAttachedStream struct {
	headerHash headerHash
	version    Version
	encoder    encoder
	buffer     bytes.Buffer
	block      []byte
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
		headerHash: headerHash,
		version:    version,
		encoder:    newEncoder(w),
		block:      make([]byte, signatureBlockSize),
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

	for s.buffer.Len() >= signatureBlockSize {
		if err := s.signBlock(false); err != nil {
			return 0, err
		}
	}

	return n, nil
}

func (s *signAttachedStream) Close() error {
	for s.buffer.Len() > 0 {
		if err := s.signBlock(false); err != nil {
			return err
		}
	}
	return s.writeFooter()
}

func makeSignatureBlock(version Version, chunk, sig []byte, isFinal bool) interface{} {
	sb := signatureBlock{
		PayloadChunk: chunk,
		Signature:    sig,
	}
	return sb
}

func (s *signAttachedStream) signBlock(isFinal bool) error {
	n, err := s.buffer.Read(s.block[:])
	if err != nil {
		return err
	}
	return s.signBytes(s.block[:n], isFinal)
}

func (s *signAttachedStream) signBytes(b []byte, isFinal bool) error {
	sig, err := s.computeSig(b, s.seqno)
	if err != nil {
		return err
	}

	sBlock := makeSignatureBlock(s.version, b, sig, isFinal)
	if err := s.encoder.Encode(sBlock); err != nil {
		return err
	}

	s.seqno++
	return nil
}

func (s *signAttachedStream) writeFooter() error {
	return s.signBytes([]byte{}, true)
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
