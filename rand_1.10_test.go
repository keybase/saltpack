// Copyright 2018 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"io"
	mathrand "math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

type testReaderSource struct {
	t    *testing.T
	r    io.Reader
	read []byte
}

var _ mathrand.Source = (*testReaderSource)(nil)

func (s *testReaderSource) Int63() int64 {
	uint32, err := cryptorandUint32(s.r)
	require.NoError(s.t, err)
	n := int64(uint32) << 31
	s.t.Logf("(1) read %x", n)
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32)
	s.read = append(s.read, buf[:]...)
	return n
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

	sourceExpected := testReaderSource{t, cryptorand.Reader, nil}
	rnd := mathrand.New(&sourceExpected)
	rnd.Shuffle(len(expectedOutput), func(i, j int) {
		t.Logf("(1) swap(%d, %d)", i, j)
		expectedOutput[i], expectedOutput[j] =
			expectedOutput[j], expectedOutput[i]
	})

	shuffle(bytes.NewBuffer(sourceExpected.read), len(output), func(i, j int) {
		t.Logf("(2) swap(%d, %d)", i, j)
		output[i], output[j] =
			output[j], output[i]
	})

	require.Equal(t, expectedOutput, output)
}
