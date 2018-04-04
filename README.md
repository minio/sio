[![Godoc Reference](https://godoc.org/github.com/minio/sio?status.svg)](https://godoc.org/github.com/minio/sio)
[![Travis CI](https://travis-ci.org/minio/sio.svg?branch=master)](https://travis-ci.org/minio/sio)
[![Go Report Card](https://goreportcard.com/badge/minio/sio)](https://goreportcard.com/report/minio/sio)

# Secure IO
## Go implementation of the Data At Rest Encryption (DARE) format.

***Abstract:** DARE is an authenticated encryption scheme to en/decrypt **and** 
authenticate/verify arbitrary long data data streams using a **constant** amount of space. Classical 
AEAD schemes - like AES-GCM - must buffer all decrypted ciphertext until its integrity is verified. 
Therefore a secure usage of such AEAD schemes require `O(|plaintext|)` space. This can cause 
performance issues and make such schemes unusable for certain kinds of streaming applications. 
DARE solves this by chunking a long data stream into smaller blobs and encrypts each blob using a 
classical AEAD such that the integrity of each blob **and** of the entire data stream can verified 
during decryption.

## Introduction

It is a common problem to store data securely - especially on untrusted remote storage. 
One solution to this problem is cryptography. Before data is stored it is encrypted
to ensure that the data is confidential. Unfortunately encrypting data is not enough to
prevent more sophisticated attacks. Anyone who has access to the stored data can try to
manipulate the data - even if the data is encrypted.

To prevent these kinds of attacks the data must be encrypted in a tamper-resistant way.
This means an attacker should not be able to:
 - Distinguish the encrypted data from a random bit string - this is achieved by modern encryption algorithms.
 - Modify the data by changing parts of the encrypted data.
 - Rearrange or reorder parts of the encrypted data. 

Authenticated encryption schemes (*AEAD*) - like AES-GCM or ChaCha20-Poly1305 - encrypt and
authenticate data. Any modification to the encrypted data (*ciphertext*) is detected while
decrypting the data. But even an *AEAD* scheme alone is not sufficiently enough to prevent all
kinds of data manipulation in certain use cases.

All modern *AEAD* schemes produce an authentication tag which can only be verified **after** 
processing the entire *ciphertext*. If a large amount of data is decrypted or the data must be 
streamed it is not always possible to buffer all decrypted data until the authentication tag is 
verified. Returning unauthenticated data has the same issues like encrypting data without 
authentication and may be a security issue.

## DARE 1.0

DARE 1.0 splits a data stream into smaller chunks and encrypts each chunk separately using
either AES256-GCM or ChaCha20Poly1305. Each chunk contains a 16 byte header, a 16 byte 
authentication tag and can contain up to 64 KB of data. Such an encrypted chunk is called *package*.
The **same** secret 256 bit key and an **unique** 96 bit *nonce* is used per package. The *nonce*
is constructed in a way such that it is not possible to add, insert or modify any data of an encrypted
data stream without breaking the security assumptions of the underlying *AEAD* scheme.
Further details can be found at the DARE 1.0 [specification](https://github.com/minio/sio/blob/master/DARE.md).

## DARE 2.0

DARE 2.0 is an improvement of DARE 1.0 and fixes a design issue affecting the integrity verification.
DARE 1.0 allows an attacker to drop **complete** packages at the end of the data stream which is not 
detected during decryption. DARE 1.0 accepts such truncated streams as valid. DARE 2.0 marks the
last package of a data stream during encryption such that the decryption can distinguish the last 
package from all other packages and fail if the last package is missing. A full specification of
DARE 2.0 is work in progress. However this repository includes a DARE 2.0 implementation which
is also selected by default.

## Secret Keys

DARE requires a **unique** 256 bit secret key per data stream. It limits the damage to some extend 
whenever a secret key is reused. Reusing a secret key **always** breaks integrity but confidentiality
is preserved to some extend. It is **highly recommended** to use an unique secret key per data 
stream like shown in this [example](https://godoc.org/github.com/minio/sio#example-Encrypt). 

## Applications

DARE is designed with simplicity and efficiency in mind. It combines modern **AEAD** schemes
with a very simple reorder protection mechanism to build a tamper-resistant encryption
scheme. DARE can be used to encrypt files, backups, video streams and even large object storage 
systems.

Its main properties are:
 - Security and high performance by relying on modern AEAD ciphers
 - Small overhead - encryption increases the amount of data by ~0.05%
 - Support for long data streams - up to 256 TB under the same key  
 - Random access - arbitrary sequences / ranges can be decrypted independently

**Install:** `go get -u github.com/minio/sio`

DARE and `github.com/minio/sio` are finalized and can be used in production.

We also provide a CLI tool to en/decrypt arbitrary data streams directly from
your command line:

**Install ncrypt:** `go get -u github.com/minio/sio/cmd/ncrypt && ncrypt -h`

## Performance

Cipher            |   8 KB   |   64 KB   |   512 KB  |  1 MB
----------------- | -------- | --------- | --------- | --------
AES_256_GCM       |  90 MB/s | 1.96 GB/s | 2.64 GB/s | 2.83 GB/s
CHACHA20_POLY1305 |  97 MB/s | 1.23 GB/s | 1.54 GB/s | 1.57 GB/s

*On i7-6500U 2 x 2.5 GHz | Linux 4.10.0-32-generic | Go 1.8.3 | AES-NI & AVX2*