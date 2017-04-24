// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"io"
)

type testSignOptions struct {
	corruptHeader      func(sh *SignatureHeader)
	corruptHeaderBytes func(bytes *[]byte)
	swapBlock          bool
	skipBlock          func(blockNum packetSeqno) bool
	skipFooter         bool
}

type testSignStream struct {
	headerHash headerHash
	encoder    encoder
	buffer     bytes.Buffer
	seqno      packetSeqno
	secretKey  SigningSecretKey
	options    testSignOptions
	savedBlock *signatureBlock
}

func newTestSignStream(version Version, w io.Writer, signer SigningSecretKey, opts testSignOptions) (*testSignStream, error) {
	if signer == nil {
		return nil, ErrInvalidParameter{message: "no signing key provided"}
	}

	header, err := newSignatureHeader(version, signer.GetPublicKey(), MessageTypeAttachedSignature)
	if err != nil {
		return nil, err
	}
	if opts.corruptHeader != nil {
		opts.corruptHeader(header)
	}

	// Encode the header bytes.
	headerBytes, err := encodeToBytes(header)
	if err != nil {
		return nil, err
	}
	if opts.corruptHeaderBytes != nil {
		opts.corruptHeaderBytes(&headerBytes)
	}

	// Compute the header hash.
	headerHash := hashHeader(headerBytes)

	stream := &testSignStream{
		headerHash: headerHash,
		encoder:    newEncoder(w),
		secretKey:  signer,
		options:    opts,
	}

	// Double encode the header bytes onto the wire.
	err = stream.encoder.Encode(headerBytes)
	if err != nil {
		return nil, err
	}

	return stream, nil
}

func (s *testSignStream) Write(p []byte) (int, error) {
	n, err := s.buffer.Write(p)
	if err != nil {
		return 0, err
	}

	for s.buffer.Len() >= signatureBlockSize {
		if err := s.signBlock(); err != nil {
			return 0, err
		}
	}

	return n, nil
}

func (s *testSignStream) Close() error {
	for s.buffer.Len() > 0 {
		if err := s.signBlock(); err != nil {
			return err
		}
	}

	if s.options.skipFooter {
		return nil
	}

	return s.signBlock()
}

func (s *testSignStream) signBlock() error {
	chunk := s.buffer.Next(signatureBlockSize)
	return s.signBytes(chunk)
}

func (s *testSignStream) signBytes(b []byte) error {
	block := signatureBlock{
		PayloadChunk: b,
	}
	sig, err := s.computeSig(b, s.seqno)
	if err != nil {
		return err
	}
	block.Signature = sig

	if s.options.swapBlock {
		if s.seqno == 0 {
			s.savedBlock = &block
			s.seqno++
			return nil
		}
	}

	if s.options.skipBlock == nil || !s.options.skipBlock(s.seqno) {
		if err := s.encoder.Encode(block); err != nil {
			return err
		}
		s.seqno++
	}

	if s.options.swapBlock {
		if s.savedBlock != nil {
			if err := s.encoder.Encode(*s.savedBlock); err != nil {
				return err
			}
			s.savedBlock = nil
			return nil
		}
	}

	return nil
}

func (s *testSignStream) computeSig(payloadChunk []byte, seqno packetSeqno) ([]byte, error) {
	return s.secretKey.Sign(attachedSignatureInput(s.headerHash, payloadChunk, seqno))
}

func testTweakSign(version Version, plaintext []byte, signer SigningSecretKey, opts testSignOptions) ([]byte, error) {
	var buf bytes.Buffer
	s, err := newTestSignStream(version, &buf, signer, opts)
	if err != nil {
		return nil, err
	}
	if _, err := s.Write(plaintext); err != nil {
		return nil, err
	}
	if err := s.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func testTweakSignDetached(version Version, plaintext []byte, signer SigningSecretKey, opts testSignOptions) ([]byte, error) {
	if signer == nil {
		return nil, ErrInvalidParameter{message: "no signing key provided"}
	}
	header, err := newSignatureHeader(version, signer.GetPublicKey(), MessageTypeDetachedSignature)
	if err != nil {
		return nil, err
	}

	if opts.corruptHeader != nil {
		opts.corruptHeader(header)
	}

	// Encode the header bytes.
	headerBytes, err := encodeToBytes(header)
	if err != nil {
		return nil, err
	}

	// Compute the header hash.
	headerHash := hashHeader(headerBytes)

	// Double encode the header bytes to start the output.
	output, err := encodeToBytes(headerBytes)
	if err != nil {
		return nil, err
	}

	// Sign the plaintext.
	signature, err := signer.Sign(detachedSignatureInput(headerHash, plaintext))
	if err != nil {
		return nil, err
	}

	// Append the encoded signature to the output.
	encodedSig, err := encodeToBytes(signature)
	if err != nil {
		return nil, err
	}
	output = append(output, encodedSig...)

	return output, nil
}
