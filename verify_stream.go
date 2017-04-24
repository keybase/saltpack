// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"fmt"
	"io"
)

type verifyStream struct {
	version    Version
	stream     *msgpackStream
	err        error
	state      readState
	buffer     []byte
	header     *SignatureHeader
	headerHash headerHash
	publicKey  SigningPublicKey
	seqno      packetSeqno
}

func newVerifyStream(versionValidator VersionValidator, r io.Reader, msgType MessageType) (*verifyStream, error) {
	s := &verifyStream{
		stream: newMsgpackStream(r),
		seqno:  0,
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
		}

		if last {
			v.state = stateEndOfStream
			// If we've reached the end of the stream, but
			// have data left (which only happens in V2),
			// return so that the next call(s) will hit
			// the case at the top, and then we'll hit the
			// case below.
			if len(v.buffer) > 0 {
				if v.version.Major < 2 {
					panic(fmt.Sprintf("version=%s, last=true, len(v.buffer)=%d > 0", v.version, len(v.buffer)))
				}

				return n, nil
			}
		}
	}

	if v.state == stateEndOfStream {
		v.err = assertEndOfStream(v.stream)
		// If V2, we can hit EOF with n > 0.
		if v.err == io.EOF {
			return n, v.err
		}
		if v.err != nil {
			return n, v.err
		}
	}

	return n, nil
}

func (v *verifyStream) readHeader(versionValidator VersionValidator, msgType MessageType) error {
	var headerBytes []byte
	_, err := v.stream.Read(&headerBytes)
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

func (v *verifyStream) readBlock(p []byte) (int, bool, error) {
	var block signatureBlock
	_, err := v.stream.Read(&block)
	if err != nil {
		return 0, false, err
	}
	seqno := v.seqno
	v.seqno++

	data, err := v.processBlock(&block, seqno)
	if err != nil {
		return 0, false, err
	}
	if data == nil || len(data) == 0 {
		return 0, true, err
	}

	n := copy(p, data)
	v.buffer = data[n:]

	return n, false, err
}

func (v *verifyStream) processBlock(block *signatureBlock, seqno packetSeqno) ([]byte, error) {
	if err := v.publicKey.Verify(attachedSignatureInput(v.headerHash, block.PayloadChunk, seqno), block.Signature); err != nil {
		return nil, err
	}
	return block.PayloadChunk, nil
}
