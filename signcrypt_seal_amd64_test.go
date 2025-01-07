// Copyright 2018 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

//go:build amd64
// +build amd64

package saltpack

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckSigncryptReceiverCountAMD64(t *testing.T) {
	err := checkSigncryptReceiverCount(maxReceiverCount, 1)
	require.Equal(t, ErrBadReceivers, err)

	err = checkSigncryptReceiverCount(1, maxReceiverCount)
	require.Equal(t, ErrBadReceivers, err)

	err = checkSigncryptReceiverCount(maxReceiverCount, maxReceiverCount)
	require.Equal(t, ErrBadReceivers, err)
}
