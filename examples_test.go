// Copyright (C) 2017 Minio Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sio

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

func ExampleEncrypt() {
	// the master key used to derive encryption keys
	// this key must be keep secret
	masterkey, err := hex.DecodeString("000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000") // use your own key here
	if err != nil {
		fmt.Printf("Cannot decode hex key: %v", err) // add error handling
		return
	}

	// generate a random nonce to derive an encryption key from the master key
	// this nonce must be saved to be able to decrypt the data again - it is not
	// required to keep it secret
	var nonce [32]byte
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		fmt.Printf("Failed to read random data: %v", err) // add error handling
		return
	}

	// derive an encryption key from the master key and the nonce
	var key [32]byte
	kdf := hkdf.New(sha256.New, masterkey, nonce[:], nil)
	if _, err = io.ReadFull(kdf, key[:]); err != nil {
		fmt.Printf("Failed to derive encryption key: %v", err) // add error handling
		return
	}

	input := os.Stdin   // customize for your needs - the plaintext
	output := os.Stdout // customize from your needs - the decrypted output

	if _, err = Encrypt(output, input, Config{Key: key[:]}); err != nil {
		fmt.Printf("Failed to encrypt data: %v", err) // add error handling
		return
	}
}

func ExampleDecrypt() {
	// the master key used to derive encryption keys
	masterkey, err := hex.DecodeString("000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000") // use your own key here
	if err != nil {
		fmt.Printf("Cannot decode hex key: %v", err) // add error handling
		return
	}

	// the nonce used to derive the encryption key
	nonce, err := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001") // use your generated nonce here
	if err != nil {
		fmt.Printf("Cannot decode hex key: %v", err) // add error handling
		return
	}

	// derive the encryption key from the master key and the nonce
	var key [32]byte
	kdf := hkdf.New(sha256.New, masterkey, nonce, nil)
	if _, err = io.ReadFull(kdf, key[:]); err != nil {
		fmt.Printf("Failed to derive encryption key: %v", err) // add error handling
		return
	}

	input := os.Stdin   // customize for your needs - the encrypted data
	output := os.Stdout // customize from your needs - the decrypted output

	if _, err = Decrypt(output, input, Config{Key: key[:]}); err != nil {
		if _, ok := err.(Error); ok {
			fmt.Printf("Malformed encrypted data: %v", err) // add error handling - here we know that the data is malformed/not authentic.
			return
		}
		fmt.Printf("Failed to decrypt data: %v", err) // add error handling
		return
	}
}

func ExampleEncryptReader() {
	// the master key used to derive encryption keys
	// this key must be keep secret
	masterkey, err := hex.DecodeString("000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000") // use your own key here
	if err != nil {
		fmt.Printf("Cannot decode hex key: %v", err) // add error handling
		return
	}

	// generate a random nonce to derive an encryption key from the master key
	// this nonce must be saved to be able to decrypt the data again - it is not
	// required to keep it secret
	var nonce [32]byte
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		fmt.Printf("Failed to read random data: %v", err) // add error handling
		return
	}

	// derive an encryption key from the master key and the nonce
	var key [32]byte
	kdf := hkdf.New(sha256.New, masterkey, nonce[:], nil)
	if _, err = io.ReadFull(kdf, key[:]); err != nil {
		fmt.Printf("Failed to derive encryption key: %v", err) // add error handling
		return
	}

	input := os.Stdin // customize for your needs - the plaintext input
	encrypted, err := EncryptReader(input, Config{Key: key[:]})
	if err != nil {
		fmt.Printf("Failed to encrypted reader: %v", err) // add error handling
		return
	}

	// the encrypted io.Reader can be used like every other reader - e.g. for copying
	if _, err := io.Copy(os.Stdout, encrypted); err != nil {
		fmt.Printf("Failed to copy data: %v", err) // add error handling
		return
	}
}

func ExampleEncryptWriter() {
	// the master key used to derive encryption keys
	// this key must be keep secret
	masterkey, err := hex.DecodeString("000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000") // use your own key here
	if err != nil {
		fmt.Printf("Cannot decode hex key: %v", err) // add error handling
		return
	}

	// generate a random nonce to derive an encryption key from the master key
	// this nonce must be saved to be able to decrypt the data again - it is not
	// required to keep it secret
	var nonce [32]byte
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		fmt.Printf("Failed to read random data: %v", err) // add error handling
		return
	}

	// derive an encryption key from the master key and the nonce
	var key [32]byte
	kdf := hkdf.New(sha256.New, masterkey, nonce[:], nil)
	if _, err = io.ReadFull(kdf, key[:]); err != nil {
		fmt.Printf("Failed to derive encryption key: %v", err) // add error handling
		return
	}

	output := os.Stdout // customize for your needs - the encrypted output
	encrypted, err := EncryptWriter(output, Config{Key: key[:]})
	if err != nil {
		fmt.Printf("Failed to encrypted writer: %v", err) // add error handling
		return
	}

	// the encrypted io.Writer can be used now but it MUST be closed at the end to
	// finalize the encryption.
	if _, err = io.Copy(encrypted, os.Stdin); err != nil {
		fmt.Printf("Failed to copy data: %v", err) // add error handling
		return
	}
	if err = encrypted.Close(); err != nil {
		fmt.Printf("Failed to finalize encryption: %v", err) // add error handling
		return
	}
}
