// Copyright 2018 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"io"
)

// cryptorandReadFull is a thin wrapper around io.ReadFull on a given
// CSPRNG that also (paranoidly) checks the length.
func cryptorandReadFull(csprng io.Reader, b []byte) error {
	n, err := io.ReadFull(csprng, b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return ErrInsufficientRandomness
	}
	return nil
}

// cryptorandRead is like crypto/rand.Read, except it uses
// cryptorandReadFull instead of io.ReadFull.
func cryptorandRead(b []byte) error {
	return cryptorandReadFull(cryptorand.Reader, b)
}

func cryptorandUint32(csprng io.Reader) (uint32, error) {
	var buf [4]byte
	err := cryptorandReadFull(csprng, buf[:])
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint32(buf[:]), nil
}

// csprngUint32n, given a CSPRNG, returns, as a uint32, a uniformly
// distributed random number in [0, n). It is adapted from
// math/rand.int31n from go 1.10.
//
// For implementation details, see:
// https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction
// https://lemire.me/blog/2016/06/30/fast-random-shuffling
func csprngUint32n(csprng io.Reader, n uint32) (uint32, error) {
	v, err := cryptorandUint32(csprng)
	if err != nil {
		return 0, err
	}
	prod := uint64(v) * uint64(n)
	low := uint32(prod)
	if low < n {
		thresh := -n % n
		for low < thresh {
			v, err = cryptorandUint32(csprng)
			if err != nil {
				return 0, err
			}
			prod = uint64(v) * uint64(n)
			low = uint32(prod)
		}
	}
	return uint32(prod >> 32), nil
}

// csprngShuffle randomizes the order of elements given a CSPRNG. n is
// the number of elements, which must be >= 0 and < 2³¹. swap swaps
// the elements with indexes i and j.
//
// This function implements
// https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle , and is
// adapted from math/rand.Shuffle from go 1.10.
func csprngShuffle(csprng io.Reader, n int, swap func(i, j int)) error {
	if n < 0 {
		panic("csprngShuffle: n < 0")
	}
	if n > ((1 << 31) - 1) {
		panic("csprngShuffle: n >= 2³¹")
	}

	for i := n - 1; i > 0; i-- {
		j, err := csprngUint32n(csprng, uint32(i+1))
		if err != nil {
			return err
		}
		swap(i, int(j))
	}
	return nil
}
