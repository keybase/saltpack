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

func TestCSPRNGUint32nFastPath(t *testing.T) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], 0xdeadbeef)
	n, err := csprngUint32n(bytes.NewReader(buf[:]), 100)
	require.NoError(t, err)
	//   (0xdeadbeef * 100) % 0xffffffff = 4225668530 > 100,
	//
	// so the if statement is skipped, and the quotient
	//
	//   (0xdeadbeef * 100) / 0xffffffff = 86
	//
	// is returned.
	require.Equal(t, uint32(86), n)
}

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

// TestCSPRNGShuffle tests that csprngShuffle exactly matches
// math/rand.Shuffle for sizes < 2³¹. This is a robust test, since
// go's backwards compatibility guarantee also applies to the behavior
// of math/rand.Rand for a given seed.
func TestCSPRNGShuffle(t *testing.T) {
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

	read := bytes.NewReader(sourceExpected.read)
	csprngShuffle(read, len(output), func(i, j int) {
		output[i], output[j] = output[j], output[i]
	})

	require.Equal(t, expectedOutput, output)
}
