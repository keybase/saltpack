// Copyright 2018 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

// +build 386

package saltpack

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckSigncryptReceiverCount386(t *testing.T) {
	maxInt := int(^uint(0) >> 1)

	err := checkSigncryptReceiverCount(maxInt, 1)
	require.NoError(t, err)

	err = checkSigncryptReceiverCount(1, maxInt)
	require.NoError(t, err)

	err = checkSigncryptReceiverCount(maxInt, maxInt)
	require.NoError(t, err)
}
