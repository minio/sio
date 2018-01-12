# Data At Rest Encryption (DARE) - Version 1.1

## 1. Introduction

This document describes the Data At Rest Encryption (DARE) format version 1.1. 
DARE defines an authenticated encryption scheme for arbitrary long data streams.

In general DARE splits an arbitrary long data stream into smaller chunks and
encrypts each chunk separately with an authenticated encryption scheme (*AEAD*).
Therefore every chunk is extended with a *header* and an *authentication tag* to 
build a *package*. The header is 16 bytes long and contains some metadata about 
the package like a version number and cipher id. The data chunk itself is the
package payload and is 65536 bytes long. The only exception is the payload of the
last package which can be shorter. The authentication tag is also 16 bytes long.

An encrypted data stream contains up to 2<sup>32</sup> packages and each package
can contain a 64 KB payload. This implies that the longest encrypted data stream 
can be 2<sup>48</sup> bytes (256 TB) long. 
DARE encrypts a data stream using a 256 bit secret key and an AEAD cipher. The
secret key and cipher is fixed per data stream - so each package of an encrypted
data stream is encrypted with the same cipher and secret key. On the other side
the encryption *nonce* of each package is unique within a sequence of packages.
Even tough DARE contains some safety net against accidental key reuse it expects 
that the secret key is unique per data stream.

If the secret encryption key is unique DARE provides confidentially and integrity
assuming the underlying AEAD cipher is secure. Furthermore it provides random access
and the encryption / decryption is parallelizable. In contrast to an AEAD cipher -
like AES-GCM - every package is decrypted separately which avoids buffering of the
decrypted data until the authentication tag is verified. This plays a role 
especially for long data streams. If the secret encryption key is ever reused DARE 
loses its integrity property. However confidentially can still be achieved to some 
extend but this depends on the length and number of encrypted data streams.

### 1.1 Major differences from DARE 1.0

This document is a revision of the [DARE 1.0](./DARE.md) format adding a 
countermeasure against truncation attacks and slightly improving security 
properties whenever an encryption key is reused. The major differences are: 
- The payload length is fixed for a sequence and must be the same for all packages
  of the same sequence. The only exception is the last package (marked by a final 
  flag). The payload of the last package can be smaller than the payload of all
  other packages.
- The header contains a final flag indicating the last package of a sequence. 
- The random nonce is fixed within one sequence and must be the same for all   
  packages of the same sequence.

DARE 1.1 is recommended over DARE 1.0 and DARE 1.0 should only be used for legacy
reasons. DARE 1.0 is marked as deprecated.

## 2. Notation

- <code>X||Y</code>: Returns the concatenation of X and Y.
- <code>|X|</code>: Returns the length of the byte sequence X as the number of bytes.
- <code>X[i]</code>: Returns the i-th byte of the byte sequence X. 
- <code>X[i:j]</code>: Returns the sub-sequence of bytes from the byte sequence X
  starting at i (inclusive) up to j (exclusive).
- <code>max(X,Y)</code>: Returns X if `X > Y`. Otherwise it returns Y.

All numbers are represented using the little endian byte order.  

## 3. Specification

A encrypted data stream `S` is represented as a sequence of <code>0 < n ≤ 
2<sup>32</sup></code> packages. Each package <code>P<sub>i</sub></code> consists of
a 16 byte header <code>H<sub>i</sub></code>, a payload <code>A<sub>i</sub></code>
and a 16 byte authentication tag <code>T<sub>i</sub></code>. All payloads are 65536
bytes long. The only exception is the payload of the last package - 
<code>A<sub>n-1</sub></code> which can be shorter:
<code>65536 ≥ |A<sub>n-1</sub>| > 0</code>.

Header   | Payload        | Tag
---------|----------------|---------
16 bytes | 1 byte - 64 KB | 16 bytes

### 3.1 Header

The package header <code>H<sub>i</sub></code> contains the metadata of the package 
<code>P<sub>i</sub></code>:
 - **Version** - The DARE format version number <code>V<sub>i</sub></code>.
   The version number of DARE 1.1 is `0x11`.
 - **Cipher ID** - The AEAD cipher used to encrypted the package 
  <code>C<sub>i</sub></code>
 - **Payload size** - The length of the payload <code>L<sub>i</sub></code>.
  <code>L<sub>i</sub></code> is defined as:
  <code>L<sub>i</sub> = |A<sub>i</sub>| - 1</code>.  
  This ensures that the maximum payload size (64 KB) can be stored using only two
  bytes as uint16.
 - **Final flag** - The final flag <code>F<sub>i</sub></code>.  
   The final flag is zero for all packages except for the last one:
   <code>∀ F<sub>i</sub>, i < n-1: F<sub>i</sub> = 0x00</code>.  
   The final flag of the last package is the byte value 0xFF:
   <code>F<sub>n-1</sub> = 0xFF</code>.
 - **Random** - A randomly generated byte string <code>R<sub>i</sub></code>.  
   <code>R<sub>i</sub></code> is equal for all packages of the same sequence:
   <code>∀ i,j ∈ n: R<sub>i</sub> = R<sub>j</sub></code>  

Version | Cipher ID | Payload size     | Final flag | Random
--------|-----------|------------------|------------|---------
1 byte  |  1 byte   | 2 bytes / uint16 |   1 byte   | 11 bytes

DARE 1.1 supports two different AEAD ciphers defined by the cipher id:

Cipher            | Value
------------------|-------
AES-256_GCM       | 0x00
CHACHA20_POLY1305 | 0x01

### 3.2 Encryption

DARE encrypts a data stream `M` by splitting `M` into `n` data chunks <code>m<sub>i</sub></code>. Therefore DARE takes as input:
- an unique 256 bit secret key `K`.
- an AEAD cipher specified by a cipher id `C`.
- a 11 byte value `R` chosen uniformly at random.

The encryption is defined as:

1. <code>∀ i < n-1: F<sub>i</sub> = 0x00. F<sub>n-1</sub> = 0xFF</code>.
2. <code>H<sub>i</sub> = 0x11 || C || |m<sub>i</sub>| - 1 || F<sub>i</sub> ||
R</code>.
3. Let the additional data be <code>a<sub>i</sub> = H<sub>i</sub>[0:4]</code>.
4. Let the nonce be <code>N<sub>i</sub> = H<sub>i</sub>[4:16] ⊕ i</code>.
5. Generate the ciphertext and authentication tag
<code>c<sub>i</sub>,t<sub>i</sub> = E(K, N<sub>i</sub>, m<sub>i</sub>,
a<sub>i</sub>)</code>.
6. The i-th package <code>P<sub>i</sub> = H<sub>i</sub> || c<sub>i</sub> || t<sub>i</sub></code>

### 3.3 Decryption

DARE decrypts a sequence of `n` packages by decrypting the every package
<code>P<sub>i</sub></code> and building a data stream out of `n` data chunks
<code>m<sub>i</sub></code>. Therefore DARE takes as input only an unique 256 bit 
secret key `K`.

The decryption is defined as:

1. Verify that:
   - <code>∀ i < n: V<sub>i</sub> = 0x11</code> - Fail otherwise. 
   - <code>F<sub>n-1</sub> = 0xFF ∧ ∀ i < n-1: F<sub>i</sub> = 0x00</code> - Fail
      otherwise.
   - <code>∀ i,j < n: C<sub>i</sub> = C<sub>j</sub></code> - Fail otherwise.
   - <code>∀ i,j < n: R<sub>i</sub> = R<sub>j</sub></code> - Fail otherwise.
   - <code>65536 > L<sub>n-1</sub> ≥ 0 ∧ ∀ i < n-1: L<sub>i</sub> = 65535</code> - 
   Fail otherwise.
2. Let the additional data be <code>a<sub>i</sub> = H<sub>i</sub>[0:4]</code>
3. Let the nonce be <code>N<sub>i</sub> = H<sub>i</sub>[4:16] ⊕ i</code>.
4. Let the AEAD cipher `(E,D)` be fixed by the cipher id <code>C<sub>i</sub></code>.
5. Generate the plaintext and the authentication tag
   <code>p<sub>i</sub>,t<sub>i</sub> = D(K, N<sub>i</sub>, A<sub>i</sub>, 
   a<sub>i</sub>)</code>. 
6. Verify that <code>∀ i < n: t<sub>i</sub> = T<sub>i</sub></code>. Fail otherwise.
7. Let <code>m<sub>i</sub> = p<sub>i</sub></code>.

### 3.4 Choice of the package size

Although it could be defined as a user-chosen parameter, DARE fixes the size of the 
package payload. The size of the payload impacts the performance and the encryption
overhead. The encryption overhead as header and authentication is <code>0.0488% = 
32 / (32 + 65536)</code> per package. On the other hand DARE requires the whole
package (65568 bytes) to decrypt a single byte of the payload.  
Additionally a fixed payload size guarantees random access. The i-th package of an
encrypted data stream <code>P<sub>i</sub></code> starts at the 
<code>i * (32 + 65536)</code> byte. Since each package is en/decrypted separately
and the only dependency between packages is the package index `i` it is possible
to en/decrypt packages in parallel.

## 4. Security

The security considerations of DARE assumes that the underlying AEAD cipher is 
secure - in particular:
 - If the combination of secret key and encryption nonce is unique and the secret
   key is not known than the ciphertext does not reveal anything about the plaintext
   except its length.
 - If the combination of secret key and encryption nonce is unique and the secret
   key is not known than the probability <code>Pr<sub>f</sub>(C)</code> for a 
   successful package forgery is: 
    - <code>Pr<sub>f</sub>(C) = N<sup>2</sup> * 2<sup>116</sup> - N * 2<sup>89</sup> - N * 2<sup>128</sup></code> if `C` is AES-256_GCM
    - <code>Pr<sub>f</sub>(C) = ((1 - N/2<sup>128</sup>)<sup>-(1+N)/2</sup> * 32768) / 2<sup>106</sup></code> if `C` is CHACHA20_POLY1305

   where `N` is the total number of packages.

Further the security properties of DARE depend on whether the secret key is unique
or is reused to encrypt two different data streams. Therefore DARE makes two 
different security claims:
1. If the secret key is unique per data stream an adversary is not able to learn
   anything about a plaintext without breaking the assumed security properties of
   the AEAD cipher. Furthermore any modification of a data stream by an adversary
   is detected with a probability <code>P ≥ 1 - Pr<sub>f</sub>(C)</code>.
2. If a specific secret key is used to encrypt `k` data streams an adversary is not
   able to learn anything about a plaintext with a probability <code>P ≥ 1 - 
   e<sup>-k<sup>2</sup> / 2 * 2<sup>56</sup></sup></code> without breaking the 
   assumed security properties of the AEAD ciphers. Furthermore any modification of 
   a data stream by an adversary is detected with a probability 
   <code>P ≥ 1 - max(Pr<sub>f</sub>(C) , e<sup>-k<sup>2</sup> / 2 * 2<sup>56</sup></sup>)</code>.

***Lemma 1:*** *Within one sequence of <code>0 < n ≤ 2<sup>32</sup></code> packages
the encryption nonce `N` is unique.*  
The encryption nonce is defined as <code>∀ i < n: N<sub>i</sub> = R ⊕ i</code>. 
Since `i` is strictly monotonously incremented for each package it is implied that
<code>∀ i,j < n , i ≠ j: N<sub>i</sub> ≠ N<sub>j</sub></code>.

***Lemma 2:*** *If the random value `R` of every sequence of <code>0 < n ≤ 
2<sup>32</sup></code> packages is chosen uniformly at random and a fixed secret 
key `K` is used to encrypt `k` sequences than the probability of a collision of
<code>K || N<sub>k,i</sub></code> is smaller than 
<code>1 - e<sup>-k<sup>2</sup> / 2 * 2<sup>56</sup></sup></code>*.  
A collision of <code>K || N<sub>k,i</sub></code> can only appear for two different
values of `k` because of *Lemma 1*. That means that a collision of
<code>K || N<sub>k,i</sub></code> implies a collision of the random value:
<code>∃ a,b ∊ k, a ≠ b :  R<sub>a</sub> = R<sub>b</sub></code>. In the worst case
all `k`sequences consists of 2<sup>32</sup> packages which implies that the last 32 
bits of the encryption nonce takes each possible value once:
<code>∀ i < n, ∃! j < 2<sup>32</sup>: N[7:11]<sub>i</sub> = j</code> which implies
<code>∀ a,b ∊ k, ∃! i,j < 2<sup>32</sup>: N[7:11]<sub>a,i</sub> = N[7:11]<sub>b,j</sub></code>.  
That means that the last 32 bits of `R` have no impact whether `K || N` is unique
if all with `K` encrypted data streams consists of 2<sup>32</sup> packages.
In such a case the number of distinct values for `R` is reduced to 
<code>2<sup>56</sup> = 2<sup>88-32</sup></code>. Since `R` is chosen uniformly
at random the probability for a collision of `K || N` can be approximated by
<code>P(coll) ≈ 1 - e<sup>-k<sup>2</sup> / 2 * 2<sup>56</sup></sup></code> 
according to the birthday paradox.  

As soon as there is collision of the first 56 bits of the random values an adversary
can XOR the payloads of those two packages 
<code>a,b ∊ k: P<sub>a,i</sub>,P<sub>b,j</sub></code> which fullfil: 
<code>N<sub>a,i</sub> = N<sub>b,j</sub></code>. Since the first 56 bits of the 
random values are equal - <code>R[0:7]<sub>a</sub> = R[0:7]<sub>b</sub></code> -
and both encrypted data streams (a,b) consists of 2<sup>32</sup> packages such two
packages must exist. The XOR of those two payloads (ciphertexts) results in the XOR
of the plaintexts according to the properties of the supported AEAD ciphers - 
AES-GCM and ChaCha20Poly1305.  
As long as there is no collision of the first 56 bits of the random values,
`K || N` stays unique because of *Lemma 1* and an adversary is not able to learn 
anything about a plaintext without breaking the assumed security properties of
the AEAD cipher.

If the secret key `K` is unique per encrypted data stream the combination of
`K || N` is unique per package because of *Lemma 1*. That implies that an
adversary is not able to learn anything about a plaintext without breaking the
assumed security properties of the AEAD cipher. Additionally the probability
of a successfully package forgery is smaller than <code>Pr<sub>f</sub>(C)</code>. 
This directly follows from the assumed security properties of the AEAD cipher. If 
the secret key `K` is unique per encrypted data stream the encrypted data stream is 
tamper-proof.

## 5. Implementation

The following section contains some recommendations and hints about implementing
DARE 1.1.

### 5.1 Randomness

Each sequence of packages requires a 11-byte value `R` which should be chosen
uniformly at random. Therefore a cryptographically-secure pseudo-random number
generator (CRSPRNG) should be used to generate `R`. Most operating systems 
already provide such a CRSPRNG - like `/dev/urandom` under linux. Furthermore
many programming languages provide an easy-to-use interface to access a
platform-specific CRSPRNG.
Often programming languages provide an additional random number generator
(RNG) - often in the context of math package/library - which is not designed
to be cryptographically-secure and therefore must not be used.

### 5.2 Side channels

The decrypted payload of a package should never be processed before the
authentication  tag of the package is not verified. Any decrypted but not
yet verified data could be modified by an adversary. Additionally the
authentication tag should be verified using a constant-time comparison
to prevent a timing side channel. This is ideally done by the AEAD cipher
implementation itself.

## 6. Secret key

The secret key should be unique per encrypted data stream. Since it is 256 bits
long the probability of choosing a specific key more than once is negligible
(<code>< ~2<sup>-128</sup></code>) if the secret key is chosen uniformly at
random. There are multiple ways to choose a secret key:

- The secret key can be derived from a master key using a cryptographic hash
  function - like SHA3 or BLAKE2. This approach requires an additional parameter
  like a counter or a random value to derive an unique key. For example:
  1. Generate a random value `I` of at least 256 bits using a CRSPRNG.
  2. Derive the secret key `K` from the master key <code>K<sub>m</sub></code>
     like <code>K = H(K<sub>m</sub>, I)</code> where `H` is a keyed
     cryptographic hash function.
     
  The master key must be kept secret and the value `I` must be remembered
  somehow - for example stored next to the encrypted data.

- The secret key can be derived from a password. Since passwords often do
  not provide the same entropy as cryptographic keys the secret key should
  be derived using a password-based key derivation function (PBKDF) - like
  Argon2 or SCrypt. A PBKDF requires an additional parameter - often called
  salt - to randomize the key derivation. To derive a secret key from a
  password the following scheme can be used:
  1. Generate a random value `I` of at least 256 bits using a CRSPRNG.
  2. Derive a secret key `K` from the password <code>P</code> like
     <code>K = PBKDF(P, I)</code>.

  The password must be kept secret and the value `I` must be remembered
  somehow - for example stored next to the encrypted data.

There are many other ways to derive a unique secret key. However, the choice
of the key derivation mechanism depends on the exact requirements.
