// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func msg(sz int) []byte {
	res := make([]byte, sz)
	for i := 0; i < sz; i++ {
		res[i] = byte(i % 256)
	}
	return res
}

const ourBrand = "ACME"

func brandCheck(t *testing.T, received string) {
	t.Helper()
	require.Equal(t, ourBrand, received)
}

const hdr = "BEGIN ACME SALTPACK ENCRYPTED MESSAGE"
const ftr = "END ACME SALTPACK ENCRYPTED MESSAGE"

func testArmor(t *testing.T, sz int) {
	m := msg(sz)
	a, err := Armor62Seal(m, MessageTypeEncryption, ourBrand)
	require.NoError(t, err)
	m2, hdr2, ftr2, err := Armor62Open(a)
	require.NoError(t, err)
	require.Equal(t, m, m2)
	require.Equal(t, hdr, hdr2)
	require.Equal(t, ftr, ftr2)
}

func TestArmor128(t *testing.T) {
	testArmor(t, 128)
}

func TestArmor512(t *testing.T) {
	testArmor(t, 512)
}

func TestArmor1024(t *testing.T) {
	testArmor(t, 1024)
}

func TestArmor8192(t *testing.T) {
	testArmor(t, 8192)
}
func TestArmor65536(t *testing.T) {
	testArmor(t, 65536)
}

func TestSlowWriter(t *testing.T) {
	m := msg(1024 * 16)
	var out bytes.Buffer
	enc, err := NewArmor62EncoderStream(&out, MessageTypeEncryption, ourBrand)
	require.NoError(t, err)
	for _, c := range m {
		_, err = enc.Write([]byte{c})
		require.NoError(t, err)
	}
	err = enc.Close()
	require.NoError(t, err)
	m2, hdr2, ftr2, err := Armor62Open(out.String())
	require.NoError(t, err)
	require.Equal(t, m, m2)
	require.Equal(t, hdr, hdr2)
	require.Equal(t, ftr, ftr2)
}

type slowReader struct {
	buf []byte
}

func (sr *slowReader) Read(b []byte) (int, error) {
	if len(sr.buf) == 0 {
		return 0, io.EOF
	}
	b[0] = sr.buf[0]
	sr.buf = sr.buf[1:]
	return 1, nil
}

func TestSlowReader(t *testing.T) {
	var sr slowReader
	m := msg(1024 * 32)
	a, err := Armor62Seal(m, MessageTypeEncryption, ourBrand)
	require.NoError(t, err)
	sr.buf = []byte(a)
	dec, frame, err := NewArmor62DecoderStream(&sr)
	require.NoError(t, err)
	m2, err := ioutil.ReadAll(dec)
	require.NoError(t, err)
	require.Equal(t, m, m2)
	hdr2, err := frame.GetHeader()
	require.NoError(t, err)
	require.Equal(t, hdr, hdr2)
	ftr2, err := frame.GetFooter()
	require.NoError(t, err)
	require.Equal(t, ftr, ftr2)
}

func TestBinaryInput(t *testing.T) {
	in, err := hex.DecodeString("96a873616c747061636b92010002c420c4afc00d50af5072094609199b54a5f8cf7b03bcea3d4945b2bbd50ac1cd42ecc41014bf77454c0b028cb009d06019981a75c4401a451af65fa3b40ae2be73b5c17dc2657992337c98ad75d4fe21de37fba2329b4970defbea176c98d306d0d285ffaa515b630224836b2c55ba1b6ba026a62102")
	require.NoError(t, err)

	done := make(chan bool)
	var m []byte
	var hdr, ftr string
	go func() {
		m, hdr, ftr, err = Armor62Open(string(in))
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		buf := make([]byte, 1<<16)
		runtime.Stack(buf, true)
		os.Stderr.Write(buf)
		t.Fatal("timed out waiting for Armor62Open to finish")
	}

	// Armor62Open should try to find the punctuation for the
	// header and hit EOF.
	require.Equal(t, io.ErrUnexpectedEOF, err, "Armor62Open didn't return io.ErrUnexpectedEOF: m == %v, hdr == %q, ftr == %q, err == %v", m, hdr, ftr, err)
}
