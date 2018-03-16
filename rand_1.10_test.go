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

func TestCSPRNGUint32Error(t *testing.T) {
	var buf [3]byte
	r := bytes.NewReader(buf[:])
	_, err := csprngUint32(r)
	require.Equal(t, io.ErrUnexpectedEOF, err)
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

// A flag controlling whether to run long-running tests that is false
// by default.
var long = flag.Bool("long", false, "whether to run long-running tests")

func testCSPRNGUint32nUniform(t *testing.T, n uint32) {
	if !*long {
		t.Skip()
	}

	// Split the 32-bit range into roughly equal ranges for each
	// worker and have each worker keep a count of how many times
	// each number is returned.

	workerCount := runtime.NumCPU()
	workerBuckets := make([][]uint64, workerCount)
	for i := 0; i < workerCount; i++ {
		workerBuckets[i] = make([]uint64, n)
	}

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
		go func(workerNum int, start, end uint64, bucket *[]uint64) {
			defer w.Done()

			var buf [4]byte
			r := bytes.NewReader(buf[:])
			for j := start; j < end; j++ {
				if j%10000000 == 0 {
					fmt.Printf("worker %d/%d: %.2f%% done\n", i+1, workerCount, float64(j-start)*100/float64(end-start))
				}

				binary.BigEndian.PutUint32(buf[:], uint32(j))
				r.Seek(0, io.SeekStart)
				m, err := csprngUint32n(r, n)
				if err != nil {
					require.Equal(t, io.EOF, err)
				} else {
					(*bucket)[m]++
				}
			}
		}(i, start, end, &workerBuckets[i])
	}

	w.Wait()

	// Then add together all the counts. Each number should appear
	// exactly floor(2³²/n) times.

	buckets := make([]uint64, n)
	for i := uint32(0); i < n; i++ {
		for j := 0; j < workerCount; j++ {
			buckets[i] += workerBuckets[j][i]
		}
	}

	for i := uint32(0); i < n; i++ {
		assert.Equal(t, uint64((1<<32)/uint64(n)), buckets[i], "i=%d", i)
	}
}

func TestCSPRNGUint32nUniform49(t *testing.T) {
	// 49 is coprime to 2³².
	testCSPRNGUint32nUniform(t, 49)
}

func TestCSPRNGUint32nUniform100(t *testing.T) {
	// 100 shares a factor with 2³².
	testCSPRNGUint32nUniform(t, 100)
}

func TestCSPRNGUint32nUniform65536(t *testing.T) {
	// 65536 divides 2³².
	testCSPRNGUint32nUniform(t, 65536)
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

	// Assumes that cryptorandUint32 uses big endian.
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
