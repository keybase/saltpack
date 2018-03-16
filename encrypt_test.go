// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

type ephemeralKeyCreator struct{}

func (c ephemeralKeyCreator) CreateEphemeralKey() (BoxSecretKey, error) {
	return createEphemeralKey(false)
}

type boxPublicKey struct {
	ephemeralKeyCreator
	key  RawBoxKey
	hide bool
}

type boxSecretKey struct {
	pub    boxPublicKey
	key    RawBoxKey
	isInit bool
	hide   bool
}

type keyring struct {
	ephemeralKeyCreator
	keys      map[string]BoxSecretKey
	sigKeys   map[string]SigningSecretKey
	blacklist map[string]struct{}
	iterable  bool
	bad       bool
}

func newKeyring() *keyring {
	return &keyring{
		keys:      make(map[string]BoxSecretKey),
		sigKeys:   make(map[string]SigningSecretKey),
		blacklist: make(map[string]struct{}),
	}
}

func (r *keyring) insert(k BoxSecretKey) {
	r.keys[hex.EncodeToString(k.GetPublicKey().ToKID())] = k
}

func (r *keyring) insertSigningKey(k SigningSecretKey) {
	r.sigKeys[hex.EncodeToString(k.GetPublicKey().ToKID())] = k
}

func (r *keyring) LookupBoxPublicKey(kid []byte) BoxPublicKey {
	if _, found := r.blacklist[hex.EncodeToString(kid)]; found {
		return nil
	}
	ret := boxPublicKey{key: sliceToByte32(kid)}
	return &ret
}

func (r *keyring) LookupSigningPublicKey(kid []byte) SigningPublicKey {
	key, ok := r.sigKeys[hex.EncodeToString(kid)]
	if !ok {
		return nil
	}
	return key.GetPublicKey()
}

func (r *keyring) ImportBoxEphemeralKey(kid []byte) BoxPublicKey {
	ret := &boxPublicKey{}
	if len(kid) != len(ret.key) {
		return nil
	}
	ret.key = sliceToByte32(kid)
	return ret
}

func (r *keyring) GetAllBoxSecretKeys() (ret []BoxSecretKey) {
	if r.iterable {
		for _, v := range r.keys {
			ret = append(ret, v)
		}
	}
	return ret
}

func createEphemeralKey(hide bool) (BoxSecretKey, error) {
	pk, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ret := &boxSecretKey{}
	ret.key = *sk
	ret.pub.key = *pk
	ret.isInit = true
	ret.hide = hide
	return ret, nil
}

func (r *keyring) makeIterable() *keyring {
	return &keyring{
		keys:     r.keys,
		iterable: true,
	}
}

func (r *keyring) LookupBoxSecretKey(kids [][]byte) (int, BoxSecretKey) {
	for i, kid := range kids {
		if key, _ := r.keys[hex.EncodeToString(kid)]; key != nil {
			if r.bad {
				return (len(kids)*4 + i), key
			}
			return i, key
		}
	}
	return -1, nil
}

func (b boxPublicKey) ToRawBoxKeyPointer() *RawBoxKey {
	return &b.key
}

func (b boxPublicKey) ToKID() []byte {
	return b.key[:]
}

func (b boxPublicKey) HideIdentity() bool { return b.hide }

func (b boxSecretKey) GetPublicKey() BoxPublicKey {
	ret := b.pub
	ret.hide = b.hide
	return ret
}

type boxPrecomputedSharedKey RawBoxKey

func (b boxSecretKey) Precompute(peer BoxPublicKey) BoxPrecomputedSharedKey {
	var res boxPrecomputedSharedKey
	box.Precompute((*[32]byte)(&res), (*[32]byte)(peer.ToRawBoxKeyPointer()), (*[32]byte)(&b.key))
	return res
}

func (b boxPrecomputedSharedKey) Unbox(nonce Nonce, msg []byte) ([]byte, error) {
	out, ok := box.OpenAfterPrecomputation([]byte{}, msg, (*[24]byte)(&nonce), (*[32]byte)(&b))
	if !ok {
		return nil, errPublicKeyDecryptionFailed
	}
	return out, nil
}

func (b boxPrecomputedSharedKey) Box(nonce Nonce, msg []byte) []byte {
	out := box.SealAfterPrecomputation([]byte{}, msg, (*[24]byte)(&nonce), (*[32]byte)(&b))
	return out
}

func (b boxSecretKey) Box(receiver BoxPublicKey, nonce Nonce, msg []byte) []byte {
	ret := box.Seal([]byte{}, msg, (*[24]byte)(&nonce),
		(*[32]byte)(receiver.ToRawBoxKeyPointer()), (*[32]byte)(&b.key))
	return ret
}

var errPublicKeyDecryptionFailed = errors.New("public key decryption failed")
var errPublicKeyEncryptionFailed = errors.New("public key encryption failed")

func (b boxSecretKey) Unbox(sender BoxPublicKey, nonce Nonce, msg []byte) ([]byte, error) {
	out, ok := box.Open([]byte{}, msg, (*[24]byte)(&nonce),
		(*[32]byte)(sender.ToRawBoxKeyPointer()), (*[32]byte)(&b.key))
	if !ok {
		return nil, errPublicKeyDecryptionFailed
	}
	return out, nil
}

var kr = newKeyring()

func (b boxSecretKey) IsNull() bool { return !b.isInit }

func newHiddenBoxKeyNoInsert(t *testing.T) BoxSecretKey {
	ret, err := createEphemeralKey(true)
	require.NoError(t, err)
	return ret
}

func newHiddenBoxKey(t *testing.T) BoxSecretKey {
	ret := newHiddenBoxKeyNoInsert(t)
	kr.insert(ret)
	return ret
}

func newBoxKeyNoInsert(t *testing.T) BoxSecretKey {
	ret, err := createEphemeralKey(false)
	require.NoError(t, err)
	return ret
}

func newBoxKey(t *testing.T) BoxSecretKey {
	ret := newBoxKeyNoInsert(t)
	kr.insert(ret)
	return ret
}

func newBoxKeyBlacklistPublic(t *testing.T) BoxSecretKey {
	ret := newBoxKey(t)
	kr.blacklist[hex.EncodeToString(ret.GetPublicKey().ToKID())] = struct{}{}
	return ret
}

func randomMsg(t *testing.T, sz int) []byte {
	out := make([]byte, sz)
	err := csprngRead(out)
	require.NoError(t, err)
	return out
}

type options struct {
	readSize int
}

func slowRead(r io.Reader, sz int) ([]byte, error) {
	buf := make([]byte, sz)
	var res []byte
	for eof := false; !eof; {
		n, err := r.Read(buf)
		res = append(res, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func isValidPermutation(n int, a []int) bool {
	if len(a) != n {
		return false
	}

	aCopy := make([]int, len(a))
	copy(aCopy, a)
	sort.Ints(aCopy)
	for i := 0; i < len(a); i++ {
		if aCopy[i] != i {
			return false
		}
	}

	return true
}

func isValidNonTrivialPermutation(n int, a []int) bool {
	if !isValidPermutation(n, a) {
		return false
	}

	// Technically this check is flaky, but the flake probability
	// is 1/n!, which is very small for n ~ 20.
	if sort.IntsAreSorted(a) {
		return false
	}

	return true
}

func getEncryptReceiverOrder(receivers []BoxPublicKey) []int {
	order := make([]int, len(receivers))
	for i, r := range receivers {
		order[i] = int(r.(boxPublicKey).key[0])
	}
	return order
}

func requireValidNonTrivialPermutation(t *testing.T, count int, shuffledOrder []int) {
	require.True(t, isValidNonTrivialPermutation(count, shuffledOrder), "shuffledOrder == %+v is an invalid or trivial permutation", shuffledOrder)
}

func TestShuffleEncryptReceivers(t *testing.T) {
	receiverCount := 20
	var receivers []BoxPublicKey
	for i := 0; i < receiverCount; i++ {
		k := boxPublicKey{
			key: RawBoxKey{byte(i)},
		}
		receivers = append(receivers, k)
	}

	shuffled, err := shuffleEncryptReceivers(receivers)
	require.NoError(t, err)

	shuffledOrder := getEncryptReceiverOrder(shuffled)
	requireValidNonTrivialPermutation(t, receiverCount, shuffledOrder)
}

func getEncryptReceiverKeysOrder(receiverKeys []receiverKeys) []int {
	order := make([]int, len(receiverKeys))
	for i, k := range receiverKeys {
		order[i] = int(k.ReceiverKID[0])
	}
	return order
}

func testNewEncryptStreamShuffledReaders(t *testing.T, version Version) {
	receiverCount := 20
	var receivers []BoxPublicKey
	for i := 0; i < receiverCount; i++ {
		k := boxPublicKey{
			key: RawBoxKey{byte(i)},
		}
		receivers = append(receivers, k)
	}

	sndr := boxSecretKey{
		key: RawBoxKey{0x08},
	}
	var ciphertext bytes.Buffer
	_, err := NewEncryptStream(version, &ciphertext, sndr, receivers)
	require.NoError(t, err)

	var headerBytes []byte
	err = decodeFromBytes(&headerBytes, ciphertext.Bytes())
	require.NoError(t, err)
	var header EncryptionHeader
	err = decodeFromBytes(&header, headerBytes)
	require.NoError(t, err)

	shuffledOrder := getEncryptReceiverKeysOrder(header.Receivers)
	requireValidNonTrivialPermutation(t, receiverCount, shuffledOrder)
}

func testRoundTrip(t *testing.T, version Version, msg []byte, receivers []BoxPublicKey, opts *options) {
	sndr := newBoxKey(t)
	var ciphertext bytes.Buffer
	if receivers == nil {
		receivers = []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	}
	strm, err := newTestEncryptStream(version, &ciphertext, sndr, receivers, ephemeralKeyCreator{},
		testEncryptionOptions{blockSize: 1024})
	require.NoError(t, err)
	_, err = strm.Write(msg)
	require.NoError(t, err)
	err = strm.Close()
	require.NoError(t, err)

	_, plaintextStream, err := NewDecryptStream(SingleVersionValidator(version), &ciphertext, kr)
	require.NoError(t, err)

	var plaintext []byte
	if opts != nil && opts.readSize != 0 {
		plaintext, err = slowRead(plaintextStream, opts.readSize)
	} else {
		plaintext, err = ioutil.ReadAll(plaintextStream)
	}
	require.NoError(t, err)
	require.Equal(t, msg, plaintext)
}

func testEmptyEncryptionOneReceiver(t *testing.T, version Version) {
	msg := []byte{}
	testRoundTrip(t, version, msg, nil, nil)
}

func testSmallEncryptionOneReceiver(t *testing.T, version Version) {
	msg := []byte("secret message!")
	testRoundTrip(t, version, msg, nil, nil)
}

func testMediumEncryptionOneReceiver(t *testing.T, version Version) {
	buf := make([]byte, 1024*10)
	err := csprngRead(buf)
	require.NoError(t, err)
	testRoundTrip(t, version, buf, nil, nil)
}

func testBiggishEncryptionOneReceiver(t *testing.T, version Version) {
	buf := make([]byte, 1024*100)
	err := csprngRead(buf)
	require.NoError(t, err)
	testRoundTrip(t, version, buf, nil, nil)
}

func testRealEncryptor(t *testing.T, version Version, sz int) {
	msg := make([]byte, sz)
	err := csprngRead(msg)
	require.NoError(t, err)
	sndr := newBoxKey(t)
	var ciphertext bytes.Buffer
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	strm, err := NewEncryptStream(version, &ciphertext, sndr, receivers)
	require.NoError(t, err)
	_, err = strm.Write(msg)
	require.NoError(t, err)
	err = strm.Close()
	require.NoError(t, err)

	mki, msg2, err := Open(SingleVersionValidator(version), ciphertext.Bytes(), kr)
	require.NoError(t, err)
	require.Equal(t, msg, msg2)
	require.False(t, mki.SenderIsAnon)
	require.False(t, mki.ReceiverIsAnon)
	require.True(t, PublicKeyEqual(sndr.GetPublicKey(), mki.SenderKey))
	require.True(t, PublicKeyEqual(receivers[0], mki.ReceiverKey.GetPublicKey()))
	require.Equal(t, 0, mki.NumAnonReceivers)
}

func testRealEncryptorSmall(t *testing.T, version Version) {
	testRealEncryptor(t, version, 101)
}

func testRealEncryptorBig(t *testing.T, version Version) {
	testRealEncryptor(t, version, 1024*1024*3)
}

func testRoundTripMedium6Receivers(t *testing.T, version Version) {
	msg := make([]byte, 1024*3)
	err := csprngRead(msg)
	require.NoError(t, err)
	receivers := []BoxPublicKey{
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKey(t).GetPublicKey(),
	}
	testRoundTrip(t, version, msg, receivers, nil)
}

func testRoundTripSmall6Receivers(t *testing.T, version Version) {
	msg := []byte("hoppy halloween")
	err := csprngRead(msg)
	require.NoError(t, err)
	receivers := []BoxPublicKey{
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKey(t).GetPublicKey(),
	}
	testRoundTrip(t, version, msg, receivers, nil)
}

func testReceiverNotFound(t *testing.T, version Version) {
	sndr := newBoxKey(t)
	msg := []byte("those who die stay with us forever, as bones")
	var out bytes.Buffer
	receivers := []BoxPublicKey{
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
	}

	strm, err := newTestEncryptStream(version, &out, sndr, receivers, ephemeralKeyCreator{},
		testEncryptionOptions{blockSize: 1024})
	require.NoError(t, err)
	_, err = strm.Write(msg)
	require.NoError(t, err)
	err = strm.Close()
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), out.Bytes(), kr)
	require.Equal(t, ErrNoDecryptionKey, err)
}

func testTruncation(t *testing.T, version Version) {
	sndr := newBoxKey(t)
	var out bytes.Buffer
	msg := []byte("this message is going to be truncated")
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	strm, err := newTestEncryptStream(version, &out, sndr, receivers, ephemeralKeyCreator{},
		testEncryptionOptions{blockSize: 1024})
	require.NoError(t, err)
	_, err = strm.Write(msg)
	require.NoError(t, err)
	err = strm.Close()
	require.NoError(t, err)

	ciphertext := out.Bytes()
	trunced1 := ciphertext[0 : len(ciphertext)-51]
	_, _, err = Open(SingleVersionValidator(version), trunced1, kr)
	require.Equal(t, io.ErrUnexpectedEOF, err)
}

func testMediumEncryptionOneReceiverSmallReads(t *testing.T, version Version) {
	buf := make([]byte, 1024*10)
	err := csprngRead(buf)
	require.NoError(t, err)
	testRoundTrip(t, version, buf, nil, &options{readSize: 1})
}

func testMediumEncryptionOneReceiverSmallishReads(t *testing.T, version Version) {
	buf := make([]byte, 1024*10)
	err := csprngRead(buf)
	require.NoError(t, err)
	testRoundTrip(t, version, buf, nil, &options{readSize: 7})
}

func testMediumEncryptionOneReceiverMediumReads(t *testing.T, version Version) {
	buf := make([]byte, 1024*10)
	err := csprngRead(buf)
	require.NoError(t, err)
	testRoundTrip(t, version, buf, nil, &options{readSize: 79})
}

func testSealAndOpen(t *testing.T, version Version, sz int) {
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	plaintext := make([]byte, sz)
	err := csprngRead(plaintext)
	require.NoError(t, err)
	ciphertext, err := Seal(version, plaintext, sender, receivers)
	require.NoError(t, err)
	_, plaintext2, err := Open(SingleVersionValidator(version), ciphertext, kr)
	require.NoError(t, err)
	require.Equal(t, plaintext, plaintext2)
}

func testSealAndOpenSmall(t *testing.T, version Version) {
	testSealAndOpen(t, version, 103)
}

func testSealAndOpenBig(t *testing.T, version Version) {
	testSealAndOpen(t, version, 1024*1024*3)
}

func testSealAndOpenTwoReceivers(t *testing.T, version Version) {
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKey(t).GetPublicKey(),
	}
	plaintext := make([]byte, 1024*10)
	err := csprngRead(plaintext)
	require.NoError(t, err)
	ciphertext, err := Seal(version, plaintext, sender, receivers)
	require.NoError(t, err)
	_, plaintext2, err := Open(SingleVersionValidator(version), ciphertext, kr)
	require.NoError(t, err)
	require.Equal(t, plaintext, plaintext2)
}

func testRepeatedKey(t *testing.T, version Version) {
	sender := newBoxKey(t)
	pk := newBoxKey(t).GetPublicKey()
	receivers := []BoxPublicKey{pk, pk}
	plaintext := randomMsg(t, 1024*3)
	_, err := Seal(version, plaintext, sender, receivers)
	require.IsType(t, ErrRepeatedKey{}, err)
}

func testEmptyReceivers(t *testing.T, version Version) {
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{}
	plaintext := randomMsg(t, 1024*3)
	_, err := Seal(version, plaintext, sender, receivers)
	require.Equal(t, ErrBadReceivers, err)
}

func testCorruptHeaderNonce(t *testing.T, version Version) {
	msg := randomMsg(t, 129)
	teo := testEncryptionOptions{
		corruptKeysNonce: func(n Nonce, rid int) Nonce {
			ret := n
			ret[4] ^= 1
			return ret
		},
	}
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	ciphertext, err := testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, errPublicKeyDecryptionFailed, err)
}

func testCorruptHeaderNonceR5(t *testing.T, version Version) {
	msg := randomMsg(t, 129)
	teo := testEncryptionOptions{
		corruptKeysNonce: func(n Nonce, rid int) Nonce {
			if rid == 5 {
				ret := n
				ret[4] ^= 1
				return ret
			}
			return n
		},
	}
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKey(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
	}
	ciphertext, err := testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, errPublicKeyDecryptionFailed, err)

	// If someone else's encryption was tampered with, we don't care and
	// shouldn't get an error.
	teo = testEncryptionOptions{
		corruptKeysNonce: func(n Nonce, rid int) Nonce {
			if rid != 5 {
				ret := n
				ret[4] ^= 1
				return ret
			}
			return n
		},
	}
	ciphertext, err = testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.NoError(t, err)
}

func testCorruptPayloadKeyBoxR5(t *testing.T, version Version) {
	msg := randomMsg(t, 129)
	teo := testEncryptionOptions{
		corruptReceiverKeys: func(keys *receiverKeys, rid int) {
			if rid == 5 {
				keys.PayloadKeyBox[35] ^= 1
			}
		},
	}
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKey(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
	}
	ciphertext, err := testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, errPublicKeyDecryptionFailed, err)

	// If someone else's encryption was tampered with, we don't care and
	// shouldn't get an error.
	teo = testEncryptionOptions{
		corruptReceiverKeys: func(keys *receiverKeys, rid int) {
			if rid != 5 {
				keys.PayloadKeyBox[35] ^= 1
			}
		},
	}
	ciphertext, err = testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.NoError(t, err)
}

func testCorruptPayloadKeyPlaintext(t *testing.T, version Version) {
	msg := randomMsg(t, 129)

	// First try flipping a bit in the payload key.
	teo := testEncryptionOptions{
		corruptPayloadKey: func(pk *[]byte, rid int) {
			if rid == 2 {
				(*pk)[3] ^= 1
			}
		},
	}
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKey(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
	}

	ciphertext, err := testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)

	// If we've corrupted the payload key, the first thing that will fail is
	// opening the sender secretbox.
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrBadSenderKeySecretbox, err)

	// Also try truncating the payload key. This should fail with a different
	// error.
	teo = testEncryptionOptions{
		corruptPayloadKey: func(pk *[]byte, rid int) {
			var shortKey [31]byte
			*pk = shortKey[:]
		},
	}
	ciphertext, err = testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrBadSymmetricKey, err)

	// Finally, do the above test again with a hidden receiver. The default
	// testing keyring is not iterable, so we need to make a new one.
	iterableKeyring := newKeyring().makeIterable()
	sender = newHiddenBoxKeyNoInsert(t)
	iterableKeyring.insert(sender)
	receivers = []BoxPublicKey{
		sender.GetPublicKey(),
	}
	ciphertext, err = testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, iterableKeyring)
	require.Equal(t, ErrBadSymmetricKey, err)
}

func testCorruptSenderSecretboxPlaintext(t *testing.T, version Version) {
	msg := randomMsg(t, 129)

	// First try flipping a bit. This should break the first payload packet.
	teo := testEncryptionOptions{
		corruptSenderKeyPlaintext: func(pk *[]byte) {
			(*pk)[3] ^= 1
		},
	}
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKey(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
	}
	ciphertext, err := testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrBadTag(1), err)

	// Also try truncating the sender key. This should hit the bad length
	// check.
	teo = testEncryptionOptions{
		corruptSenderKeyPlaintext: func(pk *[]byte) {
			var shortKey [31]byte
			copy(shortKey[:], *pk)
			*pk = shortKey[:]
		},
	}
	ciphertext, err = testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrBadBoxKey, err)
}

func testCorruptSenderSecretboxCiphertext(t *testing.T, version Version) {
	msg := randomMsg(t, 129)

	teo := testEncryptionOptions{
		corruptSenderKeyCiphertext: func(pk []byte) {
			pk[3] ^= 1
		},
	}
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKey(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
	}
	ciphertext, err := testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrBadSenderKeySecretbox, err)
}

func testMissingFooter(t *testing.T, version Version) {
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	msg := randomMsg(t, 1024*9)
	ciphertext, err := testSeal(version, msg, sender, receivers, testEncryptionOptions{
		skipFooter: true,
		blockSize:  1024,
	})
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, io.ErrUnexpectedEOF, err)
}

func getEncryptionBlockV1(eb *interface{}) encryptionBlockV1 {
	switch eb := (*eb).(type) {
	case encryptionBlockV1:
		return eb
	case encryptionBlockV2:
		return eb.encryptionBlockV1
	default:
		panic(fmt.Sprintf("Unknown type %T", eb))
	}
}

func testCorruptEncryption(t *testing.T, version Version) {
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	msg := randomMsg(t, 1024*9)

	// First check that a corrupted ciphertext fails the Poly1305
	ciphertext, err := testSeal(version, msg, sender, receivers, testEncryptionOptions{
		blockSize: 1024,
		corruptEncryptionBlock: func(eb *interface{}, ebn encryptionBlockNumber) {
			if ebn == 2 {
				ebV1 := getEncryptionBlockV1(eb)
				ebV1.PayloadCiphertext[8] ^= 1
			}
		},
	})
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrBadTag(3), err)

	// Next check that a corruption of the Poly1305 tags causes a failure
	ciphertext, err = testSeal(version, msg, sender, receivers, testEncryptionOptions{
		blockSize: 1024,
		corruptEncryptionBlock: func(eb *interface{}, ebn encryptionBlockNumber) {
			if ebn == 2 {
				ebV1 := getEncryptionBlockV1(eb)
				ebV1.HashAuthenticators[0][2] ^= 1
			}
		},
	})
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrBadTag(3), err)

	// Next check what happens if we swap nonces for blocks 0 and 1
	msg = randomMsg(t, 1024*2-1)
	ciphertext, err = testSeal(version, msg, sender, receivers, testEncryptionOptions{
		blockSize: 1024,
		corruptPayloadNonce: func(n Nonce, ebn encryptionBlockNumber) Nonce {
			switch ebn {
			case 1:
				return nonceForChunkSecretBox(encryptionBlockNumber(0))
			case 0:
				return nonceForChunkSecretBox(encryptionBlockNumber(1))
			}
			return n
		},
	})
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrBadTag(1), err)
}

func testCorruptButAuthenticPayloadBox(t *testing.T, version Version) {
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	msg := randomMsg(t, 1024*2-1)
	ciphertext, err := testSeal(version, msg, sender, receivers, testEncryptionOptions{
		corruptCiphertextBeforeHash: func(c []byte, ebn encryptionBlockNumber) {
			if ebn == 0 {
				c[0] ^= 1
			}
		},
	})
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrBadCiphertext(1), err)
}

func testCorruptNonce(t *testing.T, version Version) {
	msg := randomMsg(t, 1024*11)
	teo := testEncryptionOptions{
		blockSize: 1024,
		corruptPayloadNonce: func(n Nonce, ebn encryptionBlockNumber) Nonce {
			if ebn == 2 {
				ret := n
				ret[23]++
				return ret
			}
			return n
		},
	}
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	ciphertext, err := testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrBadTag(3), err)
}

func testCorruptHeader(t *testing.T, version Version) {
	msg := randomMsg(t, 1024*11)

	badVersion := version
	badVersion.Major++

	// Test bad Header version
	teo := testEncryptionOptions{
		blockSize: 1024,
		corruptHeader: func(eh *EncryptionHeader) {
			eh.Version = badVersion
		},
	}
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	ciphertext, err := testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrBadVersion{received: badVersion}, err)

	// Test bad header Tag
	teo = testEncryptionOptions{
		blockSize: 1024,
		corruptHeader: func(eh *EncryptionHeader) {
			eh.Type = MessageTypeAttachedSignature
		},
	}
	ciphertext, err = testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrWrongMessageType{
		wanted:   MessageTypeEncryption,
		received: MessageTypeAttachedSignature,
	}, err)

	// Corrupt Header after packing
	teo = testEncryptionOptions{
		blockSize: 1024,
		corruptHeaderPacked: func(b []byte) {
			b[0] = 0xff
			b[1] = 0xff
			b[2] = 0xff
			b[3] = 0xff
		},
	}
	ciphertext, err = testSeal(version, msg, sender, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	requireErrSuffix(t, err, "only encoded map or array can be decoded into a struct")
}

func testNoSenderKey(t *testing.T, version Version) {
	sender := newBoxKeyBlacklistPublic(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	msg := randomMsg(t, 1024*9)
	ciphertext, err := testSeal(version, msg, sender, receivers, testEncryptionOptions{
		blockSize: 1024,
	})
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrNoSenderKey, err)
}

func testSealAndOpenTrailingGarbage(t *testing.T, version Version) {
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	plaintext := randomMsg(t, 1024*3)
	ciphertext, err := Seal(version, plaintext, sender, receivers)
	require.NoError(t, err)
	var buf bytes.Buffer
	buf.Write(ciphertext)
	newEncoder(&buf).Encode(randomMsg(t, 14))
	_, _, err = Open(SingleVersionValidator(version), buf.Bytes(), kr)
	require.Equal(t, ErrTrailingGarbage, err)
}

func testAnonymousSender(t *testing.T, version Version) {
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}
	plaintext := randomMsg(t, 1024*3)
	ciphertext, err := Seal(version, plaintext, nil, receivers)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.NoError(t, err)
}

func testAllAnonymous(t *testing.T, version Version) {
	receivers := []BoxPublicKey{
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newHiddenBoxKey(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
	}
	plaintext := randomMsg(t, 1024*3)
	ciphertext, err := Seal(version, plaintext, nil, receivers)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrNoDecryptionKey, err)

	var mki *MessageKeyInfo
	mki, _, err = Open(SingleVersionValidator(version), ciphertext, kr.makeIterable())
	require.NoError(t, err)
	require.True(t, mki.SenderIsAnon)
	require.True(t, mki.ReceiverIsAnon)
	require.True(t, PublicKeyEqual(receivers[5], mki.ReceiverKey.GetPublicKey()))
	require.Equal(t, 8, mki.NumAnonReceivers)
	require.Equal(t, 0, len(mki.NamedReceivers))

	receivers[5] = newHiddenBoxKeyNoInsert(t).GetPublicKey()
	ciphertext, err = Seal(version, plaintext, nil, receivers)
	require.NoError(t, err)

	mki, _, err = Open(SingleVersionValidator(version), ciphertext, kr.makeIterable())
	require.Equal(t, ErrNoDecryptionKey, err)

	require.False(t, mki.SenderIsAnon)
	require.Nil(t, mki.ReceiverKey)
	require.Equal(t, 8, mki.NumAnonReceivers)
	require.Equal(t, 0, len(mki.NamedReceivers))

}

func testCorruptEphemeralKey(t *testing.T, version Version) {
	receivers := []BoxPublicKey{newHiddenBoxKey(t).GetPublicKey()}
	plaintext := randomMsg(t, 1024*3)
	teo := testEncryptionOptions{
		corruptHeader: func(eh *EncryptionHeader) {
			eh.Ephemeral = eh.Ephemeral[0 : len(eh.Ephemeral)-1]
		},
	}
	ciphertext, err := testSeal(version, plaintext, nil, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrBadEphemeralKey, err)
}

func testCiphertextSwapKeys(t *testing.T, version Version) {
	receivers := []BoxPublicKey{
		newBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKey(t).GetPublicKey(),
		newBoxKeyNoInsert(t).GetPublicKey(),
	}
	plaintext := randomMsg(t, 1024*3)
	teo := testEncryptionOptions{
		corruptHeader: func(h *EncryptionHeader) {
			h.Receivers[1].PayloadKeyBox, h.Receivers[0].PayloadKeyBox = h.Receivers[0].PayloadKeyBox, h.Receivers[1].PayloadKeyBox
		},
	}
	ciphertext, err := testSeal(version, plaintext, nil, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, errPublicKeyDecryptionFailed, err)
}

func testEmptyReceiverKID(t *testing.T, version Version) {
	receivers := []BoxPublicKey{
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newHiddenBoxKey(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
	}
	plaintext := randomMsg(t, 1024*3)
	teo := testEncryptionOptions{
		corruptReceiverKeys: func(keys *receiverKeys, rid int) {
			keys.ReceiverKID = []byte{}
		},
	}
	ciphertext, err := testSeal(version, plaintext, nil, receivers, teo)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrNoDecryptionKey, err)
}

func testAnonymousThenNamed(t *testing.T, version Version) {
	receivers := []BoxPublicKey{
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKey(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
	}
	plaintext := randomMsg(t, 1024*3)
	ciphertext, err := Seal(version, plaintext, nil, receivers)
	require.NoError(t, err)
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.NoError(t, err)
}

func testBadKeyLookup(t *testing.T, version Version) {
	receivers := []BoxPublicKey{
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newBoxKey(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
		newHiddenBoxKeyNoInsert(t).GetPublicKey(),
	}
	plaintext := randomMsg(t, 1024*3)
	ciphertext, err := Seal(version, plaintext, nil, receivers)
	require.NoError(t, err)
	kr.bad = true
	_, _, err = Open(SingleVersionValidator(version), ciphertext, kr)
	require.Equal(t, ErrBadLookup, err)
	kr.bad = false
}

func TestCorruptFraming(t *testing.T) {
	// Create a "ciphertext" where header packet is a type other than bytes.
	nonInteger, err := encodeToBytes(42)
	require.NoError(t, err)
	_, _, err = Open(CheckKnownMajorVersion, nonInteger, kr)
	require.Equal(t, ErrFailedToReadHeaderBytes, err)
}

func testNoWriteMessage(t *testing.T, version Version) {
	// We need to make sure the header is written out, even if we never call
	// Write() with any payload bytes.
	receivers := []BoxPublicKey{
		newBoxKey(t).GetPublicKey(),
	}
	var ciphertext bytes.Buffer
	es, err := NewEncryptStream(version, &ciphertext, nil, receivers)
	require.NoError(t, err)
	// Usually we would call Write() here. But with an empty message, we don't
	// have to!
	err = es.Close()
	require.NoError(t, err)
	_, plaintext, err := Open(SingleVersionValidator(version), ciphertext.Bytes(), kr)
	require.NoError(t, err)
	require.Equal(t, 0, len(plaintext))
}

func TestEncryptSinglePacketV1(t *testing.T) {
	sender := boxSecretKey{
		key: RawBoxKey{0x08},
	}
	receivers := []BoxPublicKey{boxPublicKey{key: RawBoxKey{0x1}}}

	plaintext := make([]byte, encryptionBlockSize)
	ciphertext, err := Seal(Version1(), plaintext, sender, receivers)
	require.NoError(t, err)

	mps := newMsgpackStream(bytes.NewReader(ciphertext))

	var headerBytes []byte
	_, err = mps.Read(&headerBytes)
	require.NoError(t, err)

	var block encryptionBlockV1

	// Payload packet.
	_, err = mps.Read(&block)
	require.NoError(t, err)

	// Empty footer payload packet.
	_, err = mps.Read(&block)
	require.NoError(t, err)

	// Nothing else.
	_, err = mps.Read(&block)
	require.Equal(t, io.EOF, err)
}

func TestEncryptSinglePacketV2(t *testing.T) {
	sender := boxSecretKey{
		key: RawBoxKey{0x08},
	}
	receivers := []BoxPublicKey{boxPublicKey{key: RawBoxKey{0x1}}}

	plaintext := make([]byte, encryptionBlockSize)
	ciphertext, err := Seal(Version2(), plaintext, sender, receivers)
	require.NoError(t, err)

	mps := newMsgpackStream(bytes.NewReader(ciphertext))

	var headerBytes []byte
	_, err = mps.Read(&headerBytes)
	require.NoError(t, err)

	var block encryptionBlockV2

	// Payload packet.
	_, err = mps.Read(&block)
	require.NoError(t, err)

	require.True(t, block.IsFinal)

	// Nothing else.
	_, err = mps.Read(&block)
	require.Equal(t, io.EOF, err)
}

func TestEncryptSubsequenceV1(t *testing.T) {
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}

	plaintext := make([]byte, 2*encryptionBlockSize)
	ciphertext, err := Seal(Version1(), plaintext, sender, receivers)
	require.NoError(t, err)

	mps := newMsgpackStream(bytes.NewReader(ciphertext))

	// These truncated ciphertexts will have the first payload
	// packet, the second payload packet, and neither payload
	// packet, respectively.
	truncatedCiphertext1 := bytes.NewBuffer(nil)
	truncatedCiphertext2 := bytes.NewBuffer(nil)
	truncatedCiphertext3 := bytes.NewBuffer(nil)
	encoder1 := newEncoder(truncatedCiphertext1)
	encoder2 := newEncoder(truncatedCiphertext2)
	encoder3 := newEncoder(truncatedCiphertext3)

	encode := func(e encoder, i interface{}) {
		err = e.Encode(i)
		require.NoError(t, err)
	}

	var headerBytes []byte
	_, err = mps.Read(&headerBytes)
	require.NoError(t, err)

	encode(encoder1, headerBytes)
	encode(encoder2, headerBytes)
	encode(encoder3, headerBytes)

	var block encryptionBlockV1

	// Payload packet 1.
	_, err = mps.Read(&block)
	require.NoError(t, err)

	encode(encoder1, block)

	// Payload packet 2.
	_, err = mps.Read(&block)
	require.NoError(t, err)

	encode(encoder2, block)

	// Empty footer payload packet.
	_, err = mps.Read(&block)
	require.NoError(t, err)

	encode(encoder1, block)
	encode(encoder2, block)
	encode(encoder3, block)

	validator := SingleVersionValidator(Version1())
	_, _, err = Open(validator, truncatedCiphertext1.Bytes(), kr)
	expectedErr := ErrBadTag(2)
	if err != expectedErr {
		t.Errorf("err=%v != %v for truncatedCiphertext1", err, expectedErr)
	}

	_, _, err = Open(validator, truncatedCiphertext2.Bytes(), kr)
	expectedErr = ErrBadTag(1)
	if err != expectedErr {
		t.Errorf("err=%v != %v for truncatedCiphertext2", err, expectedErr)
	}

	_, _, err = Open(validator, truncatedCiphertext3.Bytes(), kr)
	expectedErr = ErrBadTag(1)
	if err != expectedErr {
		t.Errorf("err=%v != %v for truncatedCiphertext3", err, expectedErr)
	}
}

func TestEncryptSubsequenceV2(t *testing.T) {
	sender := newBoxKey(t)
	receivers := []BoxPublicKey{newBoxKey(t).GetPublicKey()}

	plaintext := make([]byte, 2*encryptionBlockSize)
	ciphertext, err := Seal(Version2(), plaintext, sender, receivers)
	require.NoError(t, err)

	mps := newMsgpackStream(bytes.NewReader(ciphertext))

	// These truncated ciphertexts will have the first payload
	// packet and the second payload packet, respectively.
	truncatedCiphertext1 := bytes.NewBuffer(nil)
	truncatedCiphertext2 := bytes.NewBuffer(nil)
	encoder1 := newEncoder(truncatedCiphertext1)
	encoder2 := newEncoder(truncatedCiphertext2)

	encode := func(e encoder, i interface{}) {
		err = e.Encode(i)
		require.NoError(t, err)
	}

	var headerBytes []byte
	_, err = mps.Read(&headerBytes)
	require.NoError(t, err)

	encode(encoder1, headerBytes)
	encode(encoder2, headerBytes)

	var block encryptionBlockV2

	// Payload packet 1.
	_, err = mps.Read(&block)
	require.NoError(t, err)

	block.IsFinal = true
	encode(encoder1, block)

	// Payload packet 2.
	_, err = mps.Read(&block)
	require.NoError(t, err)

	block.IsFinal = true
	encode(encoder2, block)

	for i, truncatedCiphertext := range []*bytes.Buffer{truncatedCiphertext1, truncatedCiphertext2} {
		validator := SingleVersionValidator(Version2())
		_, _, err = Open(validator, truncatedCiphertext.Bytes(), kr)
		expectedErr := ErrBadTag(1)
		if err != expectedErr {
			t.Errorf("err=%v != %v for truncatedCiphertext%d", err, expectedErr, i+1)
		}
	}
}

func TestEncrypt(t *testing.T) {
	tests := []func(*testing.T, Version){
		testNewEncryptStreamShuffledReaders,
		testEmptyEncryptionOneReceiver,
		testSmallEncryptionOneReceiver,
		testMediumEncryptionOneReceiver,
		testBiggishEncryptionOneReceiver,
		testRealEncryptorSmall,
		testRealEncryptorBig,
		testRoundTripMedium6Receivers,
		testRoundTripSmall6Receivers,
		testReceiverNotFound,
		testTruncation,
		testMediumEncryptionOneReceiverSmallReads,
		testMediumEncryptionOneReceiverSmallishReads,
		testMediumEncryptionOneReceiverMediumReads,
		testSealAndOpenSmall,
		testSealAndOpenBig,
		testSealAndOpenTwoReceivers,
		testRepeatedKey,
		testEmptyReceivers,
		testCorruptHeaderNonce,
		testCorruptHeaderNonceR5,
		testCorruptPayloadKeyBoxR5,
		testCorruptPayloadKeyPlaintext,
		testCorruptSenderSecretboxPlaintext,
		testCorruptSenderSecretboxCiphertext,
		testMissingFooter,
		testCorruptEncryption,
		testCorruptButAuthenticPayloadBox,
		testCorruptNonce,
		testCorruptHeader,
		testNoSenderKey,
		testSealAndOpenTrailingGarbage,
		testAnonymousSender,
		testAllAnonymous,
		testCorruptEphemeralKey,
		testCiphertextSwapKeys,
		testEmptyReceiverKID,
		testAnonymousThenNamed,
		testBadKeyLookup,
		testNoWriteMessage,
	}
	runTestsOverVersions(t, "test", tests)
}

type secretKeyString string

func newRandomSecretKeyString() (secretKeyString, error) {
	_, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return secretKeyString(hex.EncodeToString((*sk)[:])), nil
}

func (s secretKeyString) toSecretKey() (boxSecretKey, error) {
	decoded, err := hex.DecodeString(string(s))
	if err != nil {
		return boxSecretKey{}, err
	}
	private := sliceToByte32(decoded)
	var public [32]byte
	curve25519.ScalarBaseMult(&public, &private)
	return boxSecretKey{
		key: private,
		pub: boxPublicKey{
			key: public,
		},
	}, nil
}

func newRandomSecretKeyStrings(n int) ([]secretKeyString, error) {
	var secretKeyStrings []secretKeyString
	for i := 0; i < n; i++ {
		s, err := newRandomSecretKeyString()
		if err != nil {
			return nil, err
		}
		secretKeyStrings = append(secretKeyStrings, s)
	}
	return secretKeyStrings, nil
}

func secretKeyStringsToPublicKeys(secretKeyStrings []secretKeyString) ([]BoxPublicKey, error) {
	var publicKeys []BoxPublicKey
	for _, s := range secretKeyStrings {
		sk, err := s.toSecretKey()
		if err != nil {
			return nil, err
		}
		publicKeys = append(publicKeys, sk.GetPublicKey())
	}
	return publicKeys, nil
}

type symmetricKeyString string

func newRandomSymmetricKeyString() (symmetricKeyString, error) {
	sk, err := newRandomSymmetricKey()
	if err != nil {
		return "", err
	}
	return symmetricKeyString(hex.EncodeToString((*sk)[:])), nil
}

func (s symmetricKeyString) toSymmetricKey() (SymmetricKey, error) {
	decoded, err := hex.DecodeString(string(s))
	if err != nil {
		return SymmetricKey{}, err
	}
	return sliceToByte32(decoded), nil
}

type constantEphemeralKeyCreator struct {
	k boxSecretKey
}

func (c constantEphemeralKeyCreator) CreateEphemeralKey() (BoxSecretKey, error) {
	return c.k, nil
}

type constantEncryptRNG struct {
	k SymmetricKey
	p []int
}

func (c constantEncryptRNG) createSymmetricKey() (*SymmetricKey, error) {
	return &c.k, nil
}

func (c constantEncryptRNG) shuffleReceivers(receivers []BoxPublicKey) ([]BoxPublicKey, error) {
	if !isValidPermutation(len(receivers), c.p) {
		return nil, fmt.Errorf("invalid permutation for length %d: %+v", len(receivers), c.p)
	}
	shuffled := make([]BoxPublicKey, len(receivers))
	for i := 0; i < len(receivers); i++ {
		shuffled[i] = receivers[c.p[i]]
	}
	return shuffled, nil
}

// encryptArmor62SealInput encapsulates all the inputs to an
// encryptArmor62Seal call, including any random state.
type encryptArmor62SealInput struct {
	// Normal input parameters to encryptArmor62Seal.

	version   Version
	plaintext string
	sender    secretKeyString
	receivers []secretKeyString
	brand     string

	// Random state.

	// The convention for permutation is that the ith shuffled
	// receiver is set to the permutation[i]th entry of receivers.
	permutation  []int
	ephemeralKey secretKeyString
	payloadKey   symmetricKeyString
}

func newRandomEncryptArmor62SealInput(
	version Version, plaintext string) (encryptArmor62SealInput, error) {
	// Hardcoded for now.
	receiverCount := 3
	receivers, err := newRandomSecretKeyStrings(receiverCount)
	if err != nil {
		return encryptArmor62SealInput{}, err
	}
	permutation := make([]int, receiverCount)
	for i := 0; i < receiverCount; i++ {
		permutation[i] = i
	}
	err = csprngShuffle(rand.Reader, receiverCount, func(i, j int) {
		permutation[i], permutation[j] = permutation[j], permutation[i]
	})
	if err != nil {
		return encryptArmor62SealInput{}, err
	}
	ephemeralKey, err := newRandomSecretKeyString()
	if err != nil {
		return encryptArmor62SealInput{}, err
	}
	payloadKey, err := newRandomSymmetricKeyString()
	if err != nil {
		return encryptArmor62SealInput{}, err
	}
	return encryptArmor62SealInput{
		version:   version,
		plaintext: plaintext,
		// Set the sender to the first receiver for now.
		sender:       receivers[0],
		receivers:    receivers,
		permutation:  permutation,
		ephemeralKey: ephemeralKey,
		payloadKey:   payloadKey,
	}, nil
}

func (i encryptArmor62SealInput) call() (string, error) {
	sender, err := i.sender.toSecretKey()
	if err != nil {
		return "", err
	}
	receivers, err := secretKeyStringsToPublicKeys(i.receivers)
	if err != nil {
		return "", err
	}
	ephemeralKey, err := i.ephemeralKey.toSecretKey()
	if err != nil {
		return "", err
	}
	payloadKey, err := i.payloadKey.toSymmetricKey()
	return encryptArmor62Seal(
		i.version,
		[]byte(i.plaintext),
		sender,
		receivers,
		constantEphemeralKeyCreator{ephemeralKey},
		constantEncryptRNG{payloadKey, i.permutation},
		i.brand)
}

// encryptArmor62SealResult encapsulates all the inputs and outputs of
// an encryptArmor62Seal call, including any random state.
type encryptArmor62SealResult struct {
	encryptArmor62SealInput

	// Output.
	armoredCiphertext string
}

func newRandomEncryptArmor62SealResult(version Version, plaintext string) (encryptArmor62SealResult, error) {
	input, err := newRandomEncryptArmor62SealInput(version, plaintext)
	if err != nil {
		return encryptArmor62SealResult{}, err
	}
	armoredCiphertext, err := input.call()
	if err != nil {
		return encryptArmor62SealResult{}, err
	}
	return encryptArmor62SealResult{
		encryptArmor62SealInput: input,
		armoredCiphertext:       armoredCiphertext,
	}, nil
}

func testEncryptArmor62SealResultSeal(t *testing.T, result encryptArmor62SealResult) {
	armoredCiphertext, err := result.encryptArmor62SealInput.call()
	require.NoError(t, err)
	require.Equal(t, result.armoredCiphertext, armoredCiphertext)
}

func TestRandomEncryptArmor62Seal(t *testing.T) {
	runTestOverVersions(t, func(t *testing.T, version Version) {
		result, err := newRandomEncryptArmor62SealResult(Version1(), "some plaintext")
		require.NoError(t, err)
		testEncryptArmor62SealResultSeal(t, result)
	})
}

var v1EncryptArmor62SealResult = encryptArmor62SealResult{
	encryptArmor62SealInput: encryptArmor62SealInput{
		version:   Version1(),
		plaintext: "hardcoded message v1",
		sender:    "4902237dc127e1cbbd5dbf0b3ce74e751aa6bbfd894f2e1658fb2c7b3b5eb9fc",
		receivers: []secretKeyString{
			// sender.
			"4902237dc127e1cbbd5dbf0b3ce74e751aa6bbfd894f2e1658fb2c7b3b5eb9fc",
			"3833f2e7bbc09b27713d4b43b03a97df784e7a0c9634d9bb1046a7354b5fa84f",
			"82f0c46354c69e360d703525a2e0b92e4cb7a64ae23bcbfbc89978ee2772fbc1",
		},
		permutation:  []int{1, 2, 0},
		ephemeralKey: "3f292760d9b325b72816d0576023292ae62d1f4190253eb40b7fcefb3b9ad41a",
		payloadKey:   "f80645613161cca059b78acda045134c3269376bcdc1b972b2f801f3a2d3d189",
	},

	armoredCiphertext: `BEGIN SALTPACK ENCRYPTED MESSAGE. kiOUtMhcc4NXXRb XMxIdgQyljprRuP QOicP26XO1b47ju UJnCDGKawXyE0lE CGP8n3qPII9mSJt qGhWH2upu3qr6yp Hvg24Iw295aGKkh fQhfQLJxJsUDR9x y2Gy6bDdEV5qptY HWjTnA0GcyYppOS SAqj0mnNeiau8bH rHTCSlbZTksMWrW 8yPAIrDuED7aB02 489C1vtaaftIWJ9 KfhuUbBL4YjA9pN YktQHwqX7zfJuEd wRhljkatr95Iiu3 1mvalHpDLlweQfd LriDGPdID6Lxy9e GXDznAHzhmHRA3p AtSuyQnPP1qGqgW Xb1gDgazh3C6Ohj 3ztzvuZdrAcGnzd IYFMr9qbtViG8v8 VWYqGIIFKdJtg8A 1MEiLMYzHd32FzH gKv6IvviDpoxpKu Cy5UKSEYxrSD9Pf lxlb8oKKg8j2App 17N21SwbQMpIWAC 56Fez3XmFCMBLp1 F25s8IysZvfRsoo K03mFwSY1s8WJNg utLmu3zfPNLWKBK ij06OwpUtfVVJMe MxNlq1XOsKFTPlD QnPpYyzQXQk5MKW hNiIRfSLuf6Emx0 zw28V3JItBtHGfv A0uYkuXwLVf6g5v 7yedpNQ04RDIWQ1 PDVSJ2z3nCEZALl DBBEo3zVk7Jx56z w8rMGGPP1mVIocY e8wc4dib0sAvfFS 7pW09TVId3jQidj xSOMMoHtCxBPRX9 lHAK4fcoKukg2Oo oizaPpY90MnJaY6 NrzVjAh2fNa7MXd RNzOJiWTLN9lnKz ZYWZ7QxkG790wQ5 8ju5Q2z5EOx1dDV dXAvS7V2HwJFsRI tPSXP84378LucSD oQqfPSz5qg. END SALTPACK ENCRYPTED MESSAGE.
`,
}

func TestSealHardcodedEncryptMessageV1(t *testing.T) {
	testEncryptArmor62SealResultSeal(t, v1EncryptArmor62SealResult)
}

var v2EncryptArmor62SealResult = encryptArmor62SealResult{
	encryptArmor62SealInput: encryptArmor62SealInput{
		version:   Version2(),
		plaintext: "hardcoded message v2",
		sender:    "16c22cb65728ded9214c8e4525decc20f6ad95fd43a503deaecdfbcd79d39d15",
		receivers: []secretKeyString{
			// sender.
			"16c22cb65728ded9214c8e4525decc20f6ad95fd43a503deaecdfbcd79d39d15",
			"fceb2cb2c77b22d47a779461c7a963a11759a3f98a437d542e3cdde5d0c9bea6",
			"293d2a95a4f6ea3ed0c5213bd9b28b28ecff5c023ad488025e2a789abb773aa5",
		},
		permutation:  []int{1, 2, 0},
		ephemeralKey: "0a3550f22ff82ca7e923ca3363d1556416d8c1df19cc372caf2661ce255f6da0",
		payloadKey:   "bf5e8f5b61c40895b53d6fa8976c22501a5b6369282e7875e528accc5e9fa70a",
	},

	armoredCiphertext: `BEGIN SALTPACK ENCRYPTED MESSAGE. kiOUtMhcc4NXXRb XMxIeCbZQsbcx3v DdVJWmdycVgmGAf 0xYSQcw1m5OoJyK bv2fcF6c2IRWvj3 2JrBxsm7P7i0fsI THRJY7du7UnaVzU FdePmD6qEnkJFFy 4NLGYijRmF4uUtE 8vE81Q7wztDuu0g sWpz2gBJWNh0Kz9 JaIgCTaNnkQFtPk hnCev1j9GycswXb DxuJkD6CtlXyWB5 PNLre4awLY5rHcS 8koY3JdVpvse9Y1 RCLRuaEqQkDTHlB XzgjHiZGmuqMwi0 eHWegV3oFvgGXiT CW6EBw7qek9cKZZ ANTpL4vBjcOoi0F elmMolRMkQmEmuX 9EsFVIPjetlyQr8 p2AWoWV12ZWddZe 4u1afhjsQc9BE4e rAWrMjfLKoAoIye QSQuQPDQXsY5mcb vxrZx938UrCewuC hj6kNpfq995o9Zl p35SMAW5K0lzaDh 0Gds5hZft2g94Xf jl7gJWhOkOUkbAs 4PvlKRJS82s5pwo U3qFzsKz2ZJOSrU qbnrr87ppb9ufW9 o36H7hC10tP3nIQ 3elSB3uAammMXAP BduZO4l8LmiwKBt TP1v52Em9ZkJARO pkXTjR8s9mmzjwG 0ZYtt7FN9A1WG1Q d2pHnh2t1X2Kwsb Tb4OBi4mohpNecR ENT3z738L4blLNA JGKR2N73nchK. END SALTPACK ENCRYPTED MESSAGE.
`,
}

func TestSealHardcodedEncryptMessageV2(t *testing.T) {
	testEncryptArmor62SealResultSeal(t, v2EncryptArmor62SealResult)
}
