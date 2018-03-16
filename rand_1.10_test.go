// Copyright 2018 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	mathrand "math/rand"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCSPRNGUint32(t *testing.T) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], 0xdeadbeef)
	r := bytes.NewReader(buf[:])
	n, err := csprngUint32(r)
	require.NoError(t, err)
	require.Equal(t, uint32(0xdeadbeef), n)
}

func TestCSPRNGUint32nFastPath(t *testing.T) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], 0xdeadbeef)
	r := bytes.NewReader(buf[:])
	n, err := csprngUint32n(r, 100)
	require.NoError(t, err)
	//   (0xdeadbeef * 100) % 0x100000000 = 422566844 >= 96,
	//
	// so the first sample is accepted, and the quotient
	//
	//   (0xdeadbeef * 100) / 0x100000000 = 86
	//
	// is returned.
	require.Equal(t, uint32(86), n)
	require.Equal(t, 0, r.Len())
}

func TestCSPRNGUint32nSlowPath(t *testing.T) {
	var buf [8]byte
	binary.BigEndian.PutUint32(buf[:], 0xdeadbeef+692989)
	binary.BigEndian.PutUint32(buf[4:], 0xdeadbeef)
	r := bytes.NewReader(buf[:])
	n, err := csprngUint32n(r, 100)
	require.NoError(t, err)
	//   ((0xdeadbeef + 692989) * 100) % 0x100000000 = 48 < 96,
	//
	// so the first sample is rejected, and the second sample is
	// accepted (by the same reasoning as above).
	require.Equal(t, uint32(86), n)
	require.Equal(t, 0, r.Len())
}

var long = flag.Bool("long", false, "whether to run long-running tests")

func TestCSPRNGUint32nUniform(t *testing.T) {
	if !*long {
		t.Skip()
	}

	workerCount := runtime.NumCPU()
	workerBuckets := make([][100]uint64, workerCount)

	var w sync.WaitGroup
	w.Add(workerCount)

	rangeSize := uint64(1<<32) / uint64(workerCount)

	for i := 0; i < workerCount; i++ {
		// Capture range variable.
		i := i
		start := uint64(i) * rangeSize
		end := uint64(i+1) * rangeSize
		if end > (1 << 32) {
			end = 1 << 32
		}
		go func(workerNum int, start, end uint64, bucket *[100]uint64) {
			defer w.Done()

			var buf [4]byte
			r := bytes.NewReader(buf[:])
			for j := start; j < end; j++ {
				if j%10000000 == 0 {
					fmt.Printf("worker %d/%d: %.2f%% done\n", i+1, workerCount, float64(j-start)*100/float64(end-start))
				}

				binary.BigEndian.PutUint32(buf[:], uint32(j))
				r.Seek(0, io.SeekStart)
				n, err := csprngUint32n(r, 100)
				if err != nil {
					require.Equal(t, io.EOF, err)
				} else {
					(*bucket)[n]++
				}
			}
		}(i, start, end, &workerBuckets[i])
	}

	w.Wait()

	var buckets [100]uint64
	for i := 0; i < 100; i++ {
		for j := 0; j < workerCount; j++ {
			buckets[i] += workerBuckets[j][i]
		}
	}

	for i := 0; i < 100; i++ {
		assert.Equal(t, uint64((1<<32)/100), buckets[i], "i=%d", i)
	}
}

type testReaderSource struct {
	t *testing.T
	r io.Reader
	// Stores the bytes read from r for later playback.
	read []byte
}

var _ mathrand.Source = (*testReaderSource)(nil)

func (s *testReaderSource) Int63() int64 {
	uint32, err := csprngUint32(s.r)
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

	r := bytes.NewReader(sourceExpected.read)
	csprngShuffle(r, len(output), func(i, j int) {
		output[i], output[j] = output[j], output[i]
	})

	require.Equal(t, expectedOutput, output)
	require.Equal(t, 0, r.Len())
}
