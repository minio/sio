// Copyright (C) 2025 Minio Inc.
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
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

// FuzzEncryptDecrypt tests round-trip encryption/decryption with random data
func FuzzEncryptDecrypt(f *testing.F) {
	// Add seed corpus
	f.Add([]byte(""))
	f.Add([]byte("a"))
	f.Add([]byte("hello world"))
	f.Add(bytes.Repeat([]byte("A"), 100))
	f.Add(bytes.Repeat([]byte("B"), 65536))
	f.Add(bytes.Repeat([]byte("C"), 65537))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Generate a random key
		var key [32]byte
		if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
			t.Fatal(err)
		}

		// Test both cipher suites
		for _, cipher := range []byte{AES_256_GCM, CHACHA20_POLY1305} {
			config := Config{
				Key:          key[:],
				CipherSuites: []byte{cipher},
			}

			// Encrypt
			var encrypted bytes.Buffer
			if _, err := Encrypt(&encrypted, bytes.NewReader(data), config); err != nil {
				t.Fatal(err)
			}

			// Decrypt
			var decrypted bytes.Buffer
			if _, err := Decrypt(&decrypted, &encrypted, config); err != nil {
				t.Fatalf("decryption failed with cipher %d: %v", cipher, err)
			}

			// Verify round-trip
			if !bytes.Equal(data, decrypted.Bytes()) {
				t.Fatalf("round-trip failed with cipher %d: data mismatch", cipher)
			}
		}
	})
}

// FuzzDecryptMalformed tests decryption with malformed/corrupted data
func FuzzDecryptMalformed(f *testing.F) {
	// Add seed corpus with valid encrypted data
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		f.Fatal(err)
	}

	config := Config{Key: key}

	var encrypted bytes.Buffer
	if _, err := Encrypt(&encrypted, bytes.NewReader([]byte("test data")), config); err != nil {
		f.Fatal(err)
	}

	f.Add(encrypted.Bytes())
	f.Add([]byte{0x10}) // Just a version byte
	f.Add([]byte{})     // Empty
	f.Add(bytes.Repeat([]byte{0xFF}, 100))

	f.Fuzz(func(_ *testing.T, data []byte) {
		// Decryption should never panic, even with malformed data
		var decrypted bytes.Buffer
		config := Config{Key: key}

		// We expect this to fail gracefully, not panic
		//nolint:errcheck,gosec // Intentionally ignoring errors in fuzz test
		Decrypt(&decrypted, bytes.NewReader(data), config)
		// Don't check error - we expect most random data to fail
		// The important thing is that it doesn't panic or crash
	})
}

// FuzzDecryptBuffer tests DecryptBuffer with various inputs
func FuzzDecryptBuffer(f *testing.F) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		f.Fatal(err)
	}

	config := Config{Key: key}

	// Create valid encrypted data
	var encrypted bytes.Buffer
	if _, err := Encrypt(&encrypted, bytes.NewReader([]byte("sample data for buffer decryption")), config); err != nil {
		f.Fatal(err)
	}

	f.Add(encrypted.Bytes())

	f.Fuzz(func(_ *testing.T, data []byte) {
		config := Config{Key: key}
		dst := make([]byte, 0, len(data))

		// Should not panic
		//nolint:errcheck,gosec // Intentionally ignoring errors in fuzz test
		DecryptBuffer(dst, data, config)
	})
}

// FuzzReaderWriter tests the Reader/Writer interfaces
func FuzzReaderWriter(f *testing.F) {
	f.Add([]byte("test"))
	f.Add(bytes.Repeat([]byte("x"), 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			t.Fatal(err)
		}

		config := Config{Key: key}

		// Test EncryptWriter / DecryptReader combination
		var encrypted bytes.Buffer
		encWriter, err := EncryptWriter(&encrypted, config)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := encWriter.Write(data); err != nil {
			t.Fatal(err)
		}

		if err := encWriter.Close(); err != nil {
			t.Fatal(err)
		}

		// Decrypt using Reader
		decReader, err := DecryptReader(&encrypted, config)
		if err != nil {
			t.Fatal(err)
		}

		decrypted, err := io.ReadAll(decReader)
		if err != nil {
			t.Fatalf("decrypt reader failed: %v", err)
		}

		if !bytes.Equal(data, decrypted) {
			t.Fatal("reader/writer round-trip mismatch")
		}
	})
}

// FuzzPackageBoundaries tests encryption at package boundaries (64KB)
func FuzzPackageBoundaries(f *testing.F) {
	// Test around the 64KB boundary
	f.Add(65534)  // Just under
	f.Add(65535)  // One less
	f.Add(65536)  // Exactly
	f.Add(65537)  // One more
	f.Add(131072) // Two packages

	f.Fuzz(func(t *testing.T, size int) {
		// Limit size to avoid excessive memory usage
		if size < 0 || size > 10<<20 {
			t.Skip()
		}

		data := make([]byte, size)
		if _, err := io.ReadFull(rand.Reader, data); err != nil {
			t.Fatal(err)
		}

		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			t.Fatal(err)
		}

		config := Config{Key: key}

		var encrypted bytes.Buffer
		if _, err := Encrypt(&encrypted, bytes.NewReader(data), config); err != nil {
			t.Fatal(err)
		}

		var decrypted bytes.Buffer
		if _, err := Decrypt(&decrypted, &encrypted, config); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(data, decrypted.Bytes()) {
			t.Fatal("boundary test failed")
		}
	})
}
