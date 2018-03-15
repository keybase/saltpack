// Copyright 2018 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import "encoding/binary"
import cryptorand "crypto/rand"

// cryptorandRead is a thin wrapper around crypto/rand.Read that also
// (paranoidly) checks the length.
func cryptorandRead(b []byte) error {
	n, err := cryptorand.Read(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return ErrInsufficientRandomness
	}
	return nil
}

func cryptorandUint32() (uint32, error) {
	var buf [4]byte
	err := cryptorandRead(buf[:])
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint32(buf[:]), nil
}

// uint32n returns, as a uint32, a non-negative pseudo-random number
// in [0,n).  It is adapted from math/rand.int31n from go 1.10.
//
// For implementation details, see:
// https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction
// https://lemire.me/blog/2016/06/30/fast-random-shuffling
func uint32n(n uint32) (uint32, error) {
	v, err := cryptorandUint32()
	if err != nil {
		return 0, err
	}
	prod := uint64(v) * uint64(n)
	low := uint32(prod)
	if low < n {
		thresh := -n % n
		for low < thresh {
			v, err = cryptorandUint32()
			if err != nil {
				return 0, err
			}
			prod = uint64(v) * uint64(n)
			low = uint32(prod)
		}
	}
	return uint32(prod >> 32), err
}

// shuffle pseudo-randomizes the order of elements.  n is the number
// of elements. Shuffle panics if n < 0.  swap swaps the elements with
// indexes i and j.
//
// shuffle is adapted from math/rand.Shuffle from go 1.10.
func shuffle(n int, swap func(i, j int)) error {
	if n < 0 || n > ((1<<31)-1) {
		panic("invalid argument to Shuffle")
	}

	for i := n - 1; i > 0; i-- {
		j, err := uint32n(uint32(i + 1))
		if err != nil {
			return err
		}
		swap(i, int(j))
	}
	return nil
}
