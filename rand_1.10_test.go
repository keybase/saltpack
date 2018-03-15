// Copyright 2018 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	cryptorand "crypto/rand"
	"io"
	mathrand "math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

type testReaderSource struct {
	t *testing.T
	r io.Reader
}

var _ mathrand.Source = testReaderSource{}

func (s testReaderSource) Int63() int64 {
	n, err := cryptorandUint32(s.r)
	require.NoError(s.t, err)
	return int64(n)
}

func (s testReaderSource) Seed(seed int64) {
	s.t.Fatal("testReaderSource.Seed() called unexpectedly")
}

func TestShuffle(t *testing.T) {
	input := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	expectedOutput := make([]int, len(input))
	output := make([]int, len(input))

	copy(expectedOutput, input)
	copy(output, input)

	rnd := mathrand.New(testReaderSource{t, cryptorand.Reader})
	rnd.Shuffle(len(expectedOutput), func(i, j int) {
		expectedOutput[i], expectedOutput[j] =
			expectedOutput[j], expectedOutput[i]
	})

	shuffle(cryptorand.Reader, len(output), func(i, j int) {
		output[i], output[j] =
			output[j], output[i]
	})

	require.Equal(t, expectedOutput, output)
}
