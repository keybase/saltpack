// Copyright 2024 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCodecMaxInitLenUsesAdaptiveDefault(t *testing.T) {
	// In go-codec, MaxInitLen is an element count, not a byte limit. Zero uses
	// the codec's element-size-aware default, which targets an initial allocation
	// of roughly 256 KiB and grows only as input is actually consumed.
	require.Zero(t, codecHandle().MaxInitLen)
}

func TestEncryptionHeadersAllowMoreThanOneThousandReceivers(t *testing.T) {
	receivers := make([]receiverKeys, 1001)

	encHeader := EncryptionHeader{
		FormatName: FormatName,
		Version:    Version2(),
		Type:       MessageTypeEncryption,
		Receivers:  receivers,
	}
	require.NoError(t, encHeader.validate(CheckKnownMajorVersion))

	signcryptHeader := SigncryptionHeader{
		FormatName: FormatName,
		Version:    Version2(),
		Type:       MessageTypeSigncryption,
		Receivers:  receivers,
	}
	require.NoError(t, signcryptHeader.validate())
}

func TestAuthenticatorCountMismatch(t *testing.T) {
	ds := decryptStream{
		version:      Version2(),
		position:     1,
		numReceivers: 2,
		payloadKey:   new(SymmetricKey),
	}

	tests := []struct {
		name           string
		authenticators []payloadAuthenticator
	}{
		{name: "missing authenticator", authenticators: make([]payloadAuthenticator, 1)},
		{name: "extra authenticator", authenticators: make([]payloadAuthenticator, 3)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := ds.processBlock(nil, test.authenticators, false, 1)
				require.Equal(t, ErrBadCiphertext(1), err)
			})
		})
	}
}
