# Saltpack Binary Signcryption Format

The regular encryption format provides privacy and authenticity using long-term
asymmetric keys, but sometimes that's not possible or practical:

- We might want to encrypt for a key that's shared by many recipients. Doing
  that retains privacy, but it means that the encryption step no longer
  provides authenticity. (Any of the recipients could forge the message,
  because the MAC is no longer pairwise.)
- We might want to encrypt for future recipients who haven't published any keys
  yet, using a secret that we'll distribute later.

For these cases, we need to combine encryption for privacy with signing for
authenticity. This is what the saltpack signcryption mode provides. Note that
this is [not as
simple](http://world.std.com/~dtd/sign_encrypt/sign_encrypt7.html) as layering
the encryption mode the signing mode. Note also that this gives up the
repudiability property of the encryption mode.

## Design

At a high-level, the message is encrypted once using a symmetric key, which is
shared with all recipients. The recipients may be either public Curve25519
encryption keys, or long-term 32-byte symmetric secrets. It is then signed with
a long-term signing key belonging to the sender.

The message is chunked into 1MiB (= 2^20 bytes) chunks. A sequential nonce used
for the encryption and MAC's ensures that the 1MiB chunks cannot be reordered.
The end of the message is marked with an authenticated flag to prevent
truncation attacks.

As in the encryption mode, each encrypted copy of the message encryption key is
given a recipient identifier. Unlike the encryption mode, signcryption doesn't
use the literal public key bytes as the identifier (in the case of an
asymmetric recipient), but instead an opaque identifier derived from the
recipient's key and the ephemeral sender key. This preserves recipient
anonymity by default. Applications lose the ability to make suggestions like
"your phone can't read this message, but your laptop can" based on the
recipients list, but the intention is that distributing long-term shared
symmetric keys to all of a user's devices can avoid that situation entirely.
The recipient identifiers for symmetric recipients are entirely up to the
application.

The signcryption scheme allows an anonymous sender by specifying a signing key
that is all zeroes. In this case the signature is filled with zeroes also, and
the verification step is skipped. This would be similar to using the encryption
mode with an anonymous sender and a shared asymmetric recipient key, though the
encryption mode wasn't designed with shared recipient keys in mind. (In
particular it would be very wrong to share recipient keys in the encryption
mode, if the sender was authenticated).

## Implementation

An signcrypted message is a series of concatenated [MessagePack
objects](https://github.com/msgpack/msgpack/blob/master/spec.md). The first is
a header packet, followed by one or more payload packets, the last of which is
indicated with a final packet flag.

When encoding strings, byte arrays, or arrays, pick the MessagePack
encoding that will use the fewest number of bytes.

### Header Packet
The header packet is a MessagePack array with these contents:

```
[
    format name,
    version,
    mode,
    ephemeral public key,
    sender secretbox,
    recipients list,
]
```

- The **format name** is the string "saltpack".
- The **version** is a list of the major and minor versions, currently
  `[2, 0]`, both encoded as
  [positive fixnums](https://github.com/msgpack/msgpack/blob/master/spec.md#int-format-family).
  Note that saltpack version 1 did not include a signcryption mode.
- The **mode** is the number 3, for signcryption, encoded as a
[positive fixnum](https://github.com/msgpack/msgpack/blob/master/spec.md#int-format-family).
  (1 and 2 are attached and detached signing, and 3 is signcryption.)
- The **ephemeral public key** is a NaCl public encryption key, 32 bytes. The
  ephemeral keypair is generated at random by the sender and only used for one
  message.
- The **sender secretbox** is a
  [`crypto_secretbox`](http://nacl.cr.yp.to/secretbox.html) containing the
  sender's long-term public _signing_ key, encrypted with the **payload key**
  from below.
- The **recipients list** contains a recipient pair for each recipient key,
  including an encrypted copy of the **payload key** (see
  below). Note that a MessagePack array can hold at most
  [at most 2³² &minus; 1](https://github.com/msgpack/msgpack/blob/master/spec.md#array-format-family)
  elements, so therefore an encrypted message can have at most 2³² &minus; 1
  recipients.

A recipient pair is a two-element list:

```
[
    recipient identifier,
    payload key box,
]
```

- The **recipient identifier** depends on the type of recipient key. For an
  asymmetric recipient key, the identifier is derived from shared DH output.
  For a symmetric key, the identifier is left to the application.
- The **payload key box** is a [`crypto_box`](http://nacl.cr.yp.to/box.html)
  containing a copy of the **payload key**, encrypted with the recipient's
  public key, the ephemeral private key, and a counter nonce.

#### Generating a Header Packet

When composing a message, the sender follows these steps to generate the
header:

1. Generate a random 32-byte **payload key**.
2. Generate a random ephemeral keypair, using
   [`crypto_box_keypair`](http://nacl.cr.yp.to/box.html).
3. Encrypt the sender's long-term public key _signing_ key using
   [`crypto_secretbox`](http://nacl.cr.yp.to/secretbox.html) with the **payload
   key** and the nonce `saltpack_sender_key_sbox`, to create the **sender
   secretbox**.
4. Encrypt a copy of the **payload key** for each recipient, and create an
   identifier for each resulting secretbox. The procedure here is different for
   the two different types of recipients:

   For Curve25519 recipient public keys, first derive a shared symmetric key by
   boxing 32 zero bytes with the recipient public key, the ephemeral private
   key, and the nonce `saltpack_derived_sboxkey`, and taking the last 32 bytes
   of the resulting box. Secretbox the **payload key** using this derived
   symmetric key, with the nonce `saltpack_recipsbXXXXXXXX`, where `XXXXXXXX`
   is the 8-byte big-endian unsigned recipient index. To compute the recipient
   identifier, concatenate the derived symmetric key and the
   `saltpack_recipsbXXXXXXXX` nonce together, and HMAC-SHA512 them under the
   key `saltpack signcryption box key identifier`. The identifier is the first
   32 bytes of that HMAC.

   For recipient symmetric keys, first derive a shared symmetric key.
   Concatenate the ephemeral public Curve25519 key and the recipient symmetric
   key, and HMAC-SHA512 them under the key `saltpack signcryption derived
   symmetric key`. The derived key is the first 32 bytes of that HMAC.
   Secretbox the **payload key** using this derived symmetric key, with the
   nonce `saltpack_recipsbXXXXXXXX`, where `XXXXXXXX` is the 8-byte big-endian
   unsigned recipient index. The recipient identifier in this case is up to the
   application.

5. Collect the **format name**, **version**, and **mode** into a list, followed
   by the **ephemeral public key**, the **sender secretbox**, and the nested
   **recipients list**.
6. Serialize the list from #5 into a MessagePack `array` object.
7. Take the [`crypto_hash`](http://nacl.cr.yp.to/hash.html) (SHA512) of the
   bytes from #6. This is the **header hash**.
8. Serialize the bytes from #6 *again* into a MessagePack `bin` object. These
   twice-encoded bytes are the header packet.

Encrypting the sender's long-term public key in step #3 allows Alice to stay
anonymous to eavesdroppers. If Alice wants to be anonymous to recipients as
well, she can supply an all-zero signing public key in step #3. In this case,
recipients should skip the signature verification step and indicate that the
message is from an anonymous sender.

#### Parsing a Header Packet

Recipients parse the header of a message using the following steps:

1. Deserialize the header bytes from the message stream using MessagePack.
   (What's on the wire is twice-encoded, so the result of unpacking will be
   once-encoded bytes.)
2. Compute the [`crypto_hash`](http://nacl.cr.yp.to/hash.html) (SHA512) of the
   bytes from #1 to give the **header hash**.
3. Deserialize the bytes from #1 *again* using MessagePack to give the header
   list.
4. Sanity check the **format name**, **version**, and **mode**.
5. Check to see if any of the recipient's Curve25519 private keys are in the
   recipients' list. For each private key available, and for each recipient
   entry in the list, compute the identifier as in step #4 in the previous
   section. If any of the recipient entries match, decrypt the **payload key**
   and proceed to step #7.
6. If no Curve25519 keys matched in the previous step, check whether any of the
   recipient's symmetric keys are in the message. The identifiers in this step
   are up to the application, and if the space of possible keys is very large,
   the recipient might use server assistance to look up identifiers. If any of
   the recipient entries match, decrypt the **payload key**. If not, decryption
   fails, and the client should report that the current user isn't a recipient
   of this message.
7. Open the **sender secretbox** using
   [`crypto_secretbox_open`](http://nacl.cr.yp.to/secretbox.html) with the
   **payload key** from #6 and the nonce `saltpack_sender_key_sbox`. This gives
   the **sender signing key**.

When parsing lists in general, if a list is longer than expected, clients
should allow the extra fields and ignore them. That allows us to make future
additions to the format without breaking backward compatibility.

### Payload Packets
A payload packet is a MessagePack array with these contents:

```
[
    signcrypted chunk,
    final flag,
]
```

- The **signcrypted chunk** is a chunk of plaintext bytes, max size 1 MiB,
  signed by the **sender signing key** and encrypted with the **payload key**.
- The **final flag** is a boolean, true for the final payload packet, and false
  for all other payload packets.

The sender creates the **signcrypted chunk** with the following steps. For
each 1 MiB chunk of plaintext:

1. Compute the **packet nonce**. Take the first 16 bytes of the **header
   hash**. If this is the final packet, set the least significant bit of the
   last of those bytes to one (`nonce[15] |= 0x01`), otherwise set it to zero
   (`nonce[15] &= 0xfe`). Finally, append the 8-byte unsigned big-endian packet
   number, where the first payload packet is zero.
2. Concatenate several values to form the **signature input**:
  - the constant string `saltpack encrypted signature`
  - a null byte, 0x00
  - the **header hash**
  - the **packet nonce** computed above
  - the **final flag** byte, `0x00` for false and `0x01` for true
  - the SHA512 hash of the plaintext
3. Sign the **signature input** with the sender's long-term private signing
   key, producing a 64-byte Ed25519 signature. If the sender is anonymous, the
   signature is 64 zero bytes instead.
4. Prepend that signature onto the front of the plaintext chunk.
5. Encrypt the attached signature from #4 using the **payload key** and the
   **packet nonce**.

The recipient performs those steps in reverse:

1. Compute the **packet nonce** as above.
2. Decrypt the chunk using the **payload key** and the **packet nonce**.
3. Take the first 64 bytes of the plaintext as the detached signature, and the
   rest as the payload chunk.
4. Compute the **signature input** as above.
5. Verify the detached signature from step #3 against the **signature input**.
   If the sender's public key is all zero bytes, however, then the sender is
   anonymous, and verification is skipped.
6. If the signature was valid, output the payload chunk.

If a message ends with without the last packet setting the **final flag** to
true, the receiving client must report an error that the message has been
truncated.

Unlike the twice-encoded header above, payload packets are once-encoded
directly to the output stream.

## Example

```yaml
# header packet (on the wire, this is twice-encoded)
[
  # format name
  "saltpack",
  # major and minor version
  [1, 0],
  # mode (3 = signcryption)
  3,
  # ephemeral public key
  895e690ba0fd8d15f51adf59e161af3f67518fa6e2eaadd8a666b8a1629c2349,
  # sender secretbox
  b49c4c8791cd97f2c244c637df90e343eda4aaa56e37d975d2b7c81d36f44850d77706a51e2ccd57e7f7606565db4b1e,
  # recipient pairs
  [
    # the first recipient pair
    [
      # a recipient identifier (the symmetric-vs-asymmetric type is indistinguishable)
      6dfcf73ef7ad77b0f20ea28f022647c02a3f3aaf57952a8c5cc9ecc33ca87223
      # payload key box
      c16b6126d155d7a39db20825d6c43f856689d0f8665a8da803270e0106ed91a90ef599961492bd6e49c69b43adc22724,
    ],
    # subsequent recipient pairs...
  ],
]

# payload packet
[
  # signcrypted chunk
  197b102766befc2d52d09728c0b9d749392f6a8c38229a682891c6b1ee28ce06402e53196c408dd716c2a97185270076e94a6e7bd6e549fb2935641981be1809604316e0e868260687dac537a7f4d027c9d278,
  # final flag
  True,
]
```
