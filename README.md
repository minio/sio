## Attention

This project is currently under development and should not be used in production!

# Minio - AEAD

## Introduction

It is a common problem to store data securely - especially on untrusted remote storage. 
One solution to this problem is cryptography. Before data is stored it is encrypted
to ensure that is is secret. Unfortunately encrypting data is not enough to prevent more
sophisticated attacks. Anyone who has access to the stored data can try to manipulate the
data - even if the data is encrypted.

To prevent these kinds of attacks the data must be encrypted in a tamper-resistant way.
This means an attacker should not be able to:
 - Read the stored data - this is achieved by modern encryption algorithms.
 - Modify the data by changing parts of the encrypted data.
 - Rearrange or reorder parts of the encrypted data. 

Authenticated encryption schemes (AE) - like AES-GCM or ChaCha20-Poly1305 - encrypt and
authenticate data. Any modification to the encrypted data (ciphertext) is detected while
decrypting the data. But even AE alone is not sufficient enough to prevent all kinds of
data manipulation. For further details see [link]().

This project provides a easy-to-use Go library implementing a tamper-resistant data encryption
scheme.

## Current status

The implementation is under development and things likely change. Do not use this library
expect for research or development reasons.
