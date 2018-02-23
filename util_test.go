// Copyright 2018 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func requireErrSuffix(t *testing.T, err error, suffix string) {
	t.Helper()
	require.True(t, strings.HasSuffix(err.Error(), suffix), "err=%v, suffix=%s", err, suffix)
}
