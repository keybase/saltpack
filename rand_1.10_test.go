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
	t *testing.T
	r io.Reader
	// Stores the bytes read from r for later playback.
	read []byte
}

var _ mathrand.Source = (*testReaderSource)(nil)

func (s *testReaderSource) Int63() int64 {
	uint32, err := cryptorandUint32(s.r)
	require.NoError(s.t, err)

	// math/rand.Shuffle calls r.Uint32(), which returns
	// uint32(r.src.Int63() >> 31), so we only need to fill in the
	// top 32 bits after the sign bit.
	n := int64(uint32) << 31

	// Assumes that cryptorandUint32 uses big endian. (This way,
	// we can test cryptorandUint32, too).
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32)
	s.read = append(s.read, buf[:]...)

	return n
}

func (s testReaderSource) Seed(seed int64) {
	s.t.Fatal("testReaderSource.Seed() called unexpectedly")
}

// Test that our shuffle matches exactly math/rand.Shuffle for sizes <
// 2³¹. This is a robust test, since go's backwards compatibility
// guarantee also applies to the behavior of math/rand.Rand.
func TestShuffle(t *testing.T) {
	count := 100000
	var input []int
	for i := 0; i < count; i++ {
		input = append(input, i)
	}

	expectedOutput := make([]int, len(input))
	output := make([]int, len(input))

	copy(expectedOutput, input)
	copy(output, input)

	sourceExpected := testReaderSource{t, cryptorand.Reader, nil}
	rnd := mathrand.New(&sourceExpected)
	rnd.Shuffle(len(expectedOutput), func(i, j int) {
		expectedOutput[i], expectedOutput[j] =
			expectedOutput[j], expectedOutput[i]
	})

	read := bytes.NewBuffer(sourceExpected.read)
	shuffle(read, len(output), func(i, j int) {
		output[i], output[j] = output[j], output[i]
	})

	require.Equal(t, expectedOutput, output)
}
