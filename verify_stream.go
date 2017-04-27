// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"errors"
	"fmt"
	"io"
)

type verifyStream struct {
	version    Version
	mps        *msgpackStream
	err        error
	state      readState
	buffer     []byte
	header     *SignatureHeader
	headerHash headerHash
	publicKey  SigningPublicKey
}

func newVerifyStream(versionValidator VersionValidator, r io.Reader, msgType MessageType) (*verifyStream, error) {
	s := &verifyStream{
		mps: newMsgpackStream(r),
	}
	err := s.readHeader(versionValidator, msgType)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (v *verifyStream) Read(p []byte) (n int, err error) {
	for n == 0 && err == nil {
		n, err = v.read(p)
	}
	if err == io.EOF && v.state != stateEndOfStream {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (v *verifyStream) read(p []byte) (n int, err error) {
	// Handle the case of a previous error. Just return the error again.
	if v.err != nil {
		return 0, v.err
	}

	// Handle the case first of a previous read that couldn't put
	// all of its data into the outgoing buffer.
	if len(v.buffer) > 0 {
		n := copy(p, v.buffer)
		v.buffer = v.buffer[n:]
		return n, nil
	}

	// We have two states we can be in, but we can definitely fall
	// through during one read, so be careful.

	if v.state == stateBody {
		var last bool
		n, last, v.err = v.readBlock(p)
		if v.err != nil {
			return 0, v.err
		} else if !last {
			return n, nil
		}

		v.state = stateEndOfStream
		// If we've reached the end of the stream, but have
		// data left (which only happens in V2), return so
		// that the next call(s) will hit the case at the top,
		// and then we'll hit the case below.
		if len(v.buffer) > 0 {
			switch v.version.Major {
			case 1:
				panic(fmt.Sprintf("version=%s, last=true, len(v.buffer)=%d > 0", v.version, len(v.buffer)))
			case 2:
				// Do nothing.
			default:
				panic(ErrBadVersion{v.version})
			}

			return n, nil
		}
	}

	if v.state == stateEndOfStream {
		v.err = assertEndOfStream(v.mps)
		// If V2, we can fall through here with n > 0. Even if
		// we have an error, we still want to return n, since
		// those bytes are verified (by readBlock's
		// post-condition).
		return n, v.err
	}

	panic(fmt.Sprintf("Should never get here: state=%v", v.state))
}

func (v *verifyStream) getNextChunk() ([]byte, error) {
	signature, chunk, isFinal, seqno, err := readSignatureBlock(v.version, v.mps)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}

	err = v.processBlock(signature, chunk, isFinal, seqno)
	if err != nil {
		return nil, err
	}

	// TODO: Ideally, we'd have a test exercising this case.
	if len(chunk) == 0 && (seqno != 0 || !isFinal) {
		return nil, errors.New("unexpected empty block")
	}

	if isFinal {
		return chunk, assertEndOfStream(v.mps)
	}

	return chunk, nil
}

func (v *verifyStream) readHeader(versionValidator VersionValidator, msgType MessageType) error {
	var headerBytes []byte
	_, err := v.mps.Read(&headerBytes)
	if err != nil {
		return err
	}

	v.headerHash = hashHeader(headerBytes)

	var header SignatureHeader
	err = decodeFromBytes(&header, headerBytes)
	if err != nil {
		return err
	}
	v.header = &header
	if err := header.validate(versionValidator, msgType); err != nil {
		return err
	}
	v.version = header.Version
	v.state = stateBody
	return nil
}

func readSignatureBlock(version Version, mps *msgpackStream) (signature, payloadChunk []byte, isFinal bool, seqno packetSeqno, err error) {
	defer func() {
		if err == nil {
			// The header packet picks up the zero seqno,
			// so subtract 1 to compensate for that.
			seqno--
		}
	}()

	switch version.Major {
	case 1:
		var sbV1 signatureBlockV1
		seqno, err = mps.Read(&sbV1)
		if err != nil {
			return nil, nil, false, 0, err
		}

		return sbV1.Signature, sbV1.PayloadChunk, len(sbV1.PayloadChunk) == 0, seqno, nil
	case 2:
		var sbV2 signatureBlockV2
		seqno, err = mps.Read(&sbV2)
		if err != nil {
			return nil, nil, false, 0, err
		}

		return sbV2.Signature, sbV2.PayloadChunk, sbV2.IsFinal, seqno, nil
	default:
		panic(ErrBadVersion{version})
	}
}

// readBlock reads the next signature block and copies verified data
// into p. If readBlock returns a non-nil error, then n will be 0.
func (v *verifyStream) readBlock(p []byte) (n int, lastBlock bool, err error) {
	signature, payloadChunk, isFinal, seqno, err := readSignatureBlock(v.version, v.mps)
	if err != nil {
		return 0, false, err
	}

	err = v.processBlock(signature, payloadChunk, isFinal, seqno)
	if err != nil {
		return 0, false, err
	}

	n = copy(p, payloadChunk)
	v.buffer = payloadChunk[n:]
	return n, isFinal, nil
}

func (v *verifyStream) processBlock(signature, payloadChunk []byte, isFinal bool, seqno packetSeqno) error {
	return v.publicKey.Verify(attachedSignatureInput(v.version, v.headerHash, payloadChunk, seqno, isFinal), signature)
}
