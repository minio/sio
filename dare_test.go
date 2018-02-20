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
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

var ioTests = []struct {
	datasize, buffersize, payloadsize int
}{
	{datasize: 1, buffersize: 1, payloadsize: maxPayloadSize},                                              // 0
	{datasize: 2, buffersize: 1, payloadsize: maxPayloadSize},                                              // 1
	{datasize: maxPayloadSize - 1, buffersize: 1, payloadsize: maxPayloadSize},                             // 2
	{datasize: maxPayloadSize, buffersize: 1, payloadsize: maxPayloadSize},                                 // 3
	{datasize: maxPayloadSize + 1, buffersize: 1, payloadsize: maxPayloadSize},                             // 4
	{datasize: 1, buffersize: headerSize, payloadsize: maxPayloadSize},                                     // 5
	{datasize: 1024, buffersize: headerSize, payloadsize: maxPayloadSize},                                  // 6
	{datasize: maxPayloadSize - 1, buffersize: headerSize, payloadsize: maxPayloadSize},                    // 7
	{datasize: maxPayloadSize, buffersize: headerSize, payloadsize: maxPayloadSize},                        // 8
	{datasize: maxPayloadSize + 1, buffersize: headerSize, payloadsize: maxPayloadSize},                    // 9
	{datasize: 1, buffersize: maxPayloadSize, payloadsize: maxPayloadSize},                                 // 10
	{datasize: 32 * 1024, buffersize: maxPayloadSize, payloadsize: maxPayloadSize},                         // 11
	{datasize: maxPayloadSize - 1, buffersize: maxPayloadSize, payloadsize: maxPayloadSize},                // 12
	{datasize: maxPayloadSize, buffersize: maxPayloadSize, payloadsize: maxPayloadSize},                    // 13
	{datasize: maxPayloadSize + 1, buffersize: maxPayloadSize, payloadsize: maxPayloadSize},                // 14
	{datasize: 1, buffersize: maxPayloadSize + tagSize, payloadsize: maxPayloadSize},                       // 15
	{datasize: 7 * 1024, buffersize: maxPayloadSize + tagSize, payloadsize: maxPayloadSize},                // 16
	{datasize: maxPayloadSize - 1, buffersize: maxPayloadSize + tagSize, payloadsize: maxPayloadSize},      // 17
	{datasize: maxPayloadSize, buffersize: maxPayloadSize + tagSize, payloadsize: maxPayloadSize},          // 18
	{datasize: maxPayloadSize + 1, buffersize: maxPayloadSize + tagSize, payloadsize: maxPayloadSize},      // 19
	{datasize: 1, buffersize: headerSize + maxPayloadSize + tagSize, payloadsize: maxPayloadSize},          // 20
	{datasize: 2 * maxPayloadSize, buffersize: maxPayloadSize + tagSize, payloadsize: maxPayloadSize},      // 21
	{datasize: 2*maxPayloadSize - 1, buffersize: maxPayloadSize + tagSize, payloadsize: maxPayloadSize},    // 22
	{datasize: 2*maxPayloadSize + 1, buffersize: maxPayloadSize + tagSize, payloadsize: maxPayloadSize},    // 23
	{datasize: 2*maxPayloadSize + 1024, buffersize: maxPayloadSize + tagSize, payloadsize: maxPayloadSize}, // 24
	{datasize: 1, buffersize: maxPayloadSize + 1, payloadsize: maxPayloadSize},                             // 25
	{datasize: 2 * maxPayloadSize, buffersize: maxPayloadSize + 1, payloadsize: maxPayloadSize},            // 26
	{datasize: 1024*1024 - 1, buffersize: maxPayloadSize + 1, payloadsize: maxPayloadSize},                 // 27
	{datasize: 1024 * 1024, buffersize: maxPayloadSize + 1, payloadsize: maxPayloadSize},                   // 28
	{datasize: 1024*1024 + 1, buffersize: maxPayloadSize + 1, payloadsize: maxPayloadSize},                 // 29
	{datasize: 2 * maxPayloadSize, buffersize: 1024 * 1024, payloadsize: maxPayloadSize},                   // 30
	{datasize: 3*maxPayloadSize + 1, buffersize: 3 * maxPayloadSize, payloadsize: maxPayloadSize},          // 31
	{datasize: 1024 * 1024, buffersize: 2 * 1024 * 1024, payloadsize: maxPayloadSize},                      // 32
	{datasize: maxPayloadSize + 1, buffersize: maxPayloadSize - 1, payloadsize: maxPayloadSize},            // 33
	{datasize: 1, buffersize: 1, payloadsize: 8 * 1024},                                                    // 34
	{datasize: 2, buffersize: 1, payloadsize: 16 * 1024},                                                   // 35
	{datasize: maxPayloadSize - 1, buffersize: 1, payloadsize: 8 * 1024},                                   // 36
	{datasize: maxPayloadSize, buffersize: 1, payloadsize: 16 * 1024},                                      // 37
	{datasize: maxPayloadSize + 1, buffersize: 1, payloadsize: 32 * 1024},                                  // 38
	{datasize: 2 * maxPayloadSize, buffersize: maxPayloadSize + 1, payloadsize: 32 * 1024},                 // 39
	{datasize: 1024*1024 - 1, buffersize: maxPayloadSize + 1, payloadsize: 32 * 1024},                      // 40
	{datasize: 1024 * 1024, buffersize: maxPayloadSize + 1, payloadsize: 32 * 1024},                        // 41
	{datasize: 1024*1024 + 1, buffersize: maxPayloadSize + 1, payloadsize: 32 * 1024},                      // 42
	{datasize: 2 * maxPayloadSize, buffersize: 1024 * 1024, payloadsize: 32 * 1024},                        // 43
	{datasize: 3*maxPayloadSize + 1, buffersize: 3 * maxPayloadSize, payloadsize: 1 + 32*1024},             // 44
	{datasize: 1024 * 1024, buffersize: 2 * 1024 * 1024, payloadsize: 2 + 32*1024},                         // 45
	{datasize: maxPayloadSize + 1, buffersize: maxPayloadSize - 1, payloadsize: 3 + 32*1024},               // 46

}

func dumpDareStream(strm []byte) {
	i := 0
	for {
		hdr := headerV10(strm[i : i+headerSize])

		fmt.Print("[")
		for i, b := range hdr {
			fmt.Printf("%02x", b)
			if i != len(hdr)-1 {
				fmt.Print(" ")
			}
		}
		fmt.Print("]")

		fmt.Printf(" version=0x%02x, cipher=0x%02x, len=0x%x, sequencenr=0x%x\n", hdr.Version(), hdr.Cipher(), hdr.Len(), hdr.SequenceNumber())

		i += headerSize + hdr.Len() + tagSize
		if i == len(strm) {
			break
		} else if i > len(strm) {
			panic(fmt.Sprintf("index larger than stream size, %d, %d", i, len(strm)))
		}
	}
}

func TestEncrypt(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	config := Config{Key: key}
	for i, test := range ioTests {
		data := make([]byte, test.datasize)
		if _, err := io.ReadFull(rand.Reader, data); err != nil {
			t.Fatalf("Test %d: Failed to generate random data: %v", i, err)
		}

		decrypted, output := bytes.NewBuffer(nil), bytes.NewBuffer(nil)

		if _, err := Encrypt(output, bytes.NewReader(data), config); err != nil {
			t.Errorf("Test %d: Encryption failed: %v", i, err)
		}
		// dumpDareStream(output.Bytes())
		if n, err := Decrypt(decrypted, output, config); n != int64(test.datasize) || err != nil {
			t.Errorf("Test %d: Decryption failed: number of bytes: %d - %v", i, n, err)
		}
		if !bytes.Equal(data, decrypted.Bytes()) {
			t.Errorf("Test: %d: Failed to encrypt and decrypt data", i)
		}
	}
}

func TestReader(t *testing.T) {
	config := Config{Key: make([]byte, 32)}
	for i, test := range ioTests {
		data, buffer := make([]byte, test.datasize), make([]byte, test.buffersize)
		if _, err := io.ReadFull(rand.Reader, data); err != nil {
			t.Fatalf("Test %d: Failed to generate random data: %v", i, err)
		}

		encReader, err := EncryptReader(bytes.NewReader(data), config)
		if err != nil {
			t.Fatalf("Test %d: Failed to create encrypted reader: %v", i, err)
		}
		decReader, err := DecryptReader(encReader, config)
		if err != nil {
			t.Fatalf("Test %d: Failed to create decrypted reader: %v", i, err)
		}

		_, err = io.ReadFull(decReader, buffer)
		if err == io.ErrUnexpectedEOF && test.buffersize < test.datasize {
			t.Errorf("Test %d: Reading failed: %v", i, err)
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			t.Errorf("Test %d: Reading failed: %v", i, err)
		}
	}
}

func TestWriter(t *testing.T) {
	config := Config{Key: make([]byte, 32)}
	for i, test := range ioTests {
		data := make([]byte, test.datasize)
		if _, err := io.ReadFull(rand.Reader, data); err != nil {
			t.Fatalf("Test %d: Failed to generate random data: %v", i, err)
		}

		output := bytes.NewBuffer(nil)

		decWriter, err := DecryptWriter(output, config)
		if err != nil {
			t.Fatalf("Test %d: Failed to create decrypted writer: %v", i, err)
		}
		encWriter, err := EncryptWriter(decWriter, config)
		if err != nil {
			t.Fatalf("Test %d: Failed to create encrypted writer: %v", i, err)
		}

		if _, err := encWriter.Write(data[:1]); err != nil {
			t.Errorf("Test %d: Writing failed: %v", i, err)
		}
		if _, err := encWriter.Write(data[1:]); err != nil {
			t.Errorf("Test %d: Writing failed: %v", i, err)
		}
		if err := encWriter.Close(); err != nil {
			t.Errorf("Test: %d: Failed to close writer: %v", i, err)
		}
		if !bytes.Equal(data, output.Bytes()) {
			t.Errorf("Test: %d: Failed to encrypt and decrypt data", i)
		}
	}
}

func TestCopy(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	config := Config{Key: key}
	for i, test := range ioTests {
		data, buffer := make([]byte, test.datasize), make([]byte, test.buffersize)
		if _, err := io.ReadFull(rand.Reader, data); err != nil {
			t.Fatalf("Test %d: Failed to generate random data: %v", i, err)
		}

		output := bytes.NewBuffer(nil)

		decWriter, err := DecryptWriter(output, config)
		if err != nil {
			t.Fatalf("Test %d: Failed to create decrypted writer: %v", i, err)
		}
		encReader, err := EncryptReader(bytes.NewReader(data), config)
		if err != nil {
			t.Fatalf("Test %d: Failed to create encrypted reader: %v", i, err)
		}

		if _, err := io.CopyBuffer(decWriter, encReader, buffer); err != nil {
			t.Fatalf("Test: %d: Failed to copy: %v", i, err)
		}
		if err := decWriter.Close(); err != nil {
			t.Fatalf("Test: %d: Failed to close writer: %v", i, err)
		}
		if !bytes.Equal(data, output.Bytes()) {
			t.Fatalf("Test: %d: Failed to encrypt and decrypt data", i)
		}
	}
}

type nonceGen struct{ nonce [8]byte }

func (g *nonceGen) Read(p []byte) (n int, err error) {
	n = copy(p, g.nonce[:])
	return
}

var testVectors = []struct {
	config                  Config
	data                    []byte
	header, ciphertext, tag []byte
}{
	{
		config:     Config{CipherSuites: []byte{AES_256_GCM}, Rand: &nonceGen{[8]byte{}}},
		data:       []byte{0},
		header:     []byte{16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		ciphertext: []byte{218},
		tag:        []byte{245, 10, 224, 169, 227, 81, 137, 91, 231, 37, 240, 4, 78, 104, 89, 213},
	},
	{
		config:     Config{CipherSuites: []byte{AES_256_GCM}, Rand: &nonceGen{[8]byte{1}}},
		data:       []byte{0, 1},
		header:     []byte{16, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
		ciphertext: []byte{52, 114},
		tag:        []byte{183, 185, 30, 215, 70, 86, 86, 205, 76, 247, 167, 13, 204, 212, 172, 116},
	},
	{
		config:     Config{CipherSuites: []byte{AES_256_GCM}, Rand: &nonceGen{[8]byte{2}}},
		data:       make([]byte, maxPayloadSize),
		header:     []byte{16, 0, 255, 255, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0},
		ciphertext: nil,
		tag:        []byte{139, 74, 190, 231, 245, 110, 183, 213, 6, 21, 36, 24, 19, 122, 47, 159},
	},
	{
		config: Config{CipherSuites: []byte{AES_256_GCM}, SequenceNumber: 1, Rand: &nonceGen{[8]byte{0, 0, 0, 0, 0, 0, 0, 1}}},
		data:   make([]byte, 64),
		header: []byte{16, 0, 63, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		ciphertext: []byte{
			77, 72, 228, 176, 217, 81, 153, 241, 230, 45, 149, 149, 71, 84, 134, 164, 150, 103, 100, 162, 2, 50,
			94, 110, 254, 55, 46, 37, 64, 248, 63, 156, 5, 149, 152, 104, 127, 168, 82, 20, 184, 1, 144, 28, 156,
			119, 232, 94, 126, 63, 249, 30, 31, 164, 133, 96, 166, 3, 72, 198, 206, 235, 253, 92,
		},
		tag: []byte{163, 136, 174, 122, 229, 10, 70, 60, 64, 32, 195, 193, 193, 104, 85, 63},
	},
	{
		config:     Config{CipherSuites: []byte{CHACHA20_POLY1305}, Rand: &nonceGen{[8]byte{}}},
		data:       []byte{0},
		header:     []byte{16, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		ciphertext: []byte{12},
		tag:        []byte{79, 112, 6, 156, 85, 188, 243, 92, 12, 80, 227, 149, 192, 175, 139, 205},
	},
	{
		config:     Config{CipherSuites: []byte{CHACHA20_POLY1305}, Rand: &nonceGen{[8]byte{1}}},
		data:       []byte{0, 1},
		header:     []byte{16, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
		ciphertext: []byte{203, 33},
		tag:        []byte{186, 36, 35, 49, 33, 140, 41, 11, 107, 213, 13, 52, 86, 238, 123, 138},
	},
	{
		config:     Config{CipherSuites: []byte{CHACHA20_POLY1305}, Rand: &nonceGen{[8]byte{2}}},
		data:       make([]byte, maxPayloadSize),
		header:     []byte{16, 1, 255, 255, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0},
		ciphertext: nil,
		tag:        []byte{149, 175, 36, 122, 124, 207, 137, 178, 185, 135, 112, 8, 59, 83, 132, 200},
	},
	{
		config: Config{CipherSuites: []byte{CHACHA20_POLY1305}, SequenceNumber: 1, Rand: &nonceGen{[8]byte{0, 0, 0, 0, 0, 0, 0, 1}}},
		data:   make([]byte, 64),
		header: []byte{16, 1, 63, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		ciphertext: []byte{
			23, 33, 70, 29, 195, 17, 46, 120, 240, 134, 246, 246, 127, 220, 167, 106, 121, 81, 139, 241, 223, 247,
			170, 13, 103, 14, 170, 180, 105, 217, 20, 153, 130, 246, 60, 128, 147, 232, 92, 158, 101, 221, 90, 197,
			18, 218, 210, 248, 34, 91, 17, 207, 245, 217, 85, 42, 85, 206, 91, 204, 119, 136, 246, 245,
		},
		tag: []byte{150, 8, 31, 175, 67, 252, 232, 149, 133, 137, 152, 21, 198, 248, 213, 162},
	},
}

func TestVectors(t *testing.T) {
	key, err := hex.DecodeString("000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000")
	if err != nil {
		t.Fatalf("Failed to decode key: %v", err)
	}
	for i, test := range testVectors {
		config := test.config
		config.Key = key

		output := bytes.NewBuffer(nil)
		encWriter, err := EncryptWriter(output, config)
		if err != nil {
			t.Fatalf("Test %d: Failed to create encrypted writer: %v", i, err)
		}
		if _, err = encWriter.Write(test.data); err != nil {
			t.Fatalf("Test %d: Failed to write to encrypted writer: %v", i, err)
		}
		if err = encWriter.Close(); err != nil {
			t.Fatalf("Test %d: Failed to close encrypted writer: %v", i, err)
		}

		out := output.Bytes()
		if !bytes.Equal(out[:headerSize], test.header) {
			t.Errorf("Test %d: Header does not match: got: %v want: %v", i, out[:headerSize], test.header)
		}
		if test.ciphertext != nil && !bytes.Equal(out[headerSize:len(out)-tagSize], test.ciphertext) {
			t.Errorf("Test %d: Header does not match: got: %v want: %v", i, out[headerSize:len(out)-tagSize], test.ciphertext)
		}
		if !bytes.Equal(out[len(out)-tagSize:], test.tag) {
			t.Errorf("Test %d: Header does not match: got: %v want: %v", i, out[len(out)-tagSize:], test.tag)
		}

		decrypted := make([]byte, len(test.data))
		decReader, err := DecryptReader(output, config)
		if err != nil {
			t.Fatalf("Test %d: Failed to create decrypted reader: %v", i, err)
		}
		if _, err = io.ReadFull(decReader, decrypted); err != nil {
			t.Fatalf("Test %d: Failed to read from decrypted reader: %v", i, err)
		}
		if !bytes.Equal(decrypted, test.data) {
			t.Errorf("Test %d: Failed to decrypt encrypted data", i)
		}
	}
}

var maliciousVectors = []struct {
	config                  Config
	header, ciphertext, tag []byte
	err                     error
}{
	{
		config:     Config{},
		header:     []byte{16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // header too small
		ciphertext: nil,
		tag:        nil,
		err:        errMissingHeader,
	},
	{
		config:     Config{},
		header:     []byte{15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // bad version
		ciphertext: []byte{218},
		tag:        []byte{245, 10, 224, 169, 227, 81, 137, 91, 231, 37, 240, 4, 78, 104, 89, 213},
		err:        errUnsupportedVersion,
	},
	{
		config:     Config{},
		header:     []byte{16, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // bad cipher
		ciphertext: []byte{218},
		tag:        []byte{245, 10, 224, 169, 227, 81, 137, 91, 231, 37, 240, 4, 78, 104, 89, 213},
		err:        errUnsupportedCipher,
	},
	{
		config:     Config{},
		header:     []byte{16, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // unsupported version
		ciphertext: []byte{218},
		tag:        []byte{245, 10, 224, 169, 227, 81, 137, 91, 231, 37, 240, 4, 78, 104, 89, 213},
		err:        errTagMismatch,
	},
	{
		config:     Config{},
		header:     []byte{16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // invalid sequence number
		ciphertext: []byte{218},
		tag:        []byte{245, 10, 224, 169, 227, 81, 137, 91, 231, 37, 240, 4, 78, 104, 89, 213},
		err:        errPackageOutOfOrder,
	},
	{
		config:     Config{},
		header:     []byte{16, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // wrong cipher
		ciphertext: []byte{218},
		tag:        []byte{245, 10, 224, 169, 227, 81, 137, 91, 231, 37, 240, 4, 78, 104, 89, 213},
		err:        errTagMismatch,
	},
	{
		config:     Config{},
		header:     []byte{16, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // wrong cipher
		ciphertext: []byte{218},
		tag:        []byte{245, 10, 224, 169, 227, 81, 137, 91, 231, 37, 240, 4, 78, 104, 89, 213},
		err:        errTagMismatch,
	},
	{
		config:     Config{},
		header:     []byte{16, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}, // payload length too large
		ciphertext: []byte{52, 114},
		tag:        []byte{183, 185, 30, 215, 70, 86, 86, 205, 76, 247, 167, 13, 204, 212, 172, 116},
		err:        errPayloadTooShort,
	},
	{
		config:     Config{},
		header:     []byte{16, 0, 0, 0, 0, 0, 0, 0, 146, 140, 4, 182, 237, 41, 185, 5}, // payload length is one but empty ciphertext
		ciphertext: []byte{ /*144*/ },
		tag:        []byte{104, 16, 43, 23, 1, 226, 58, 67, 55, 234, 18, 160, 64, 47, 166, 158},
		err:        errPayloadTooShort,
	},
	{
		config:     Config{},
		header:     []byte{16, 0, 2, 0, 0, 0, 0, 0, 30, 2, 115, 248, 75, 180, 105, 205}, // payload length too small (resulting in tag mismatch)
		ciphertext: []byte{30, 242, 98, 22},
		tag:        []byte{22, 194, 137, 24, 116, 52, 216, 208, 0, 244, 187, 218, 208, 6, 39, 65},
		err:        errTagMismatch,
	},
	{
		config:     Config{},
		header:     []byte{16, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
		ciphertext: []byte{52, 114, 22}, // ciphertext too long
		tag:        []byte{183, 185, 30, 215, 70, 86, 86, 205, 76, 247, 167, 13, 204, 212, 172, 116},
		err:        errTagMismatch,
	},
}

func TestMaliciousVectors(t *testing.T) {
	key, err := hex.DecodeString("000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000")
	if err != nil {
		t.Fatalf("Failed to decode key: %v", err)
	}
	for i, test := range maliciousVectors {
		config := test.config
		config.Key = key

		data := append(test.header, test.ciphertext...)
		data = append(data, test.tag...)
		buffer := make([]byte, len(data))

		reader, err := DecryptReader(bytes.NewReader(data), config)
		if err != nil {
			t.Fatalf("Test %d: failed to create decrypted reader: %v", i, err)
		}
		if _, err = reader.Read(buffer); err != test.err {
			t.Errorf("Test %d: should fail with: %v but failed with: %v", i, test.err, err)
		}

		writer, err := DecryptWriter(bytes.NewBuffer(buffer[:0]), config)
		if err != nil {
			t.Fatalf("Test %d: failed to create decrypted reader: %v", i, err)
		}
		_, wErr := writer.Write(data)
		cErr := writer.Close()
		if wErr != test.err && cErr != test.err {
			t.Errorf("Test %d: should fail with: %v but failed with: write: %v and close: %v", i, test.err, wErr, cErr)
		}
	}
}

var sequenceNumberTest = []struct {
	sequence    uint32
	packages    int
	modify      int
	badSequence uint32
}{
	{sequence: 0, packages: 5, modify: 4, badSequence: 3},
	{sequence: 1, packages: 7, modify: 2, badSequence: 4},
	{sequence: 33333, packages: 6, modify: 1, badSequence: 33333},
	{sequence: 1 << 30, packages: 5, modify: 0, badSequence: 0},
	{sequence: 4, packages: 8, modify: 7, badSequence: 13},
}

func TestVerifySequenceNumbers(t *testing.T) {
	key, err := hex.DecodeString("000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000")
	if err != nil {
		t.Fatalf("Failed to decode key: %v", err)
	}

	for i, test := range sequenceNumberTest {
		config := Config{
			Key:            key,
			SequenceNumber: test.sequence,
		}

		data := make([]byte, maxPayloadSize*test.packages)
		if _, err = io.ReadFull(rand.Reader, data); err != nil {
			t.Fatalf("Test %d: Failed to generate random data: %v", i, err)
		}
		dst := make([]byte, (headerSize+maxPayloadSize+tagSize)*test.packages)
		if _, err = Encrypt(bytes.NewBuffer(dst[:0]), bytes.NewReader(data), config); err != nil {
			t.Errorf("Test %d: Failed to encrypt data: %v", i, err)
		}

		if _, err = Decrypt(bytes.NewBuffer(nil), bytes.NewReader(dst), config); err != nil {
			t.Errorf("Test %d: Failed to decrypt data: %v", i, err)
		}

		unmodifiedHeader := make([]byte, headerSize)
		offset := (headerSize + maxPayloadSize + tagSize) * test.modify
		header := headerV10(dst[offset : offset+headerSize])
		copy(unmodifiedHeader, header)

		header.SetSequenceNumber(test.badSequence)
		if _, err = Decrypt(bytes.NewBuffer(nil), bytes.NewReader(dst), config); err == nil {
			t.Errorf("Test %d: Expected to report error while decrypting but decryption passed successfully", i)
		}

		decWriter, err := DecryptWriter(bytes.NewBuffer(nil), config)
		if err != nil {
			t.Fatalf("Test %d: Failed to create decrypting writer: %v", i, err)
		}
		if _, err = io.Copy(decWriter, bytes.NewReader(dst)); err == nil {
			t.Errorf("Test %d: Expected to report error while decrypting but decryption passed successfully", i)
		}
		copy(header, unmodifiedHeader)
	}
}

func testFile(t *testing.T, file string) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		t.Errorf("Failed to read file: %s - %v", file, err)
	}
	if err != nil || len(data) == 0 {
		return // exit out for empty files or error
	}

	key, err := hex.DecodeString("000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000")
	if err != nil {
		t.Fatalf("Failed to decode key: %v", err)
	}
	config := Config{Key: key}

	decrypted, output := bytes.NewBuffer(nil), bytes.NewBuffer(nil)

	if _, err := Encrypt(output, bytes.NewReader(data), config); err != nil {
		t.Errorf("Encryption failed: %v", err)
	}
	if n, err := Decrypt(decrypted, output, config); n != int64(len(data)) || err != nil {
		t.Errorf("Decryption failed: number of bytes: %d - %v", n, err)
	}
	if !bytes.Equal(data, decrypted.Bytes()) {
		t.Errorf("Failed to encrypt and decrypt data. %v | %v", data, decrypted.Bytes())
	}
}

func TestFiles(t *testing.T) {

	fileList := []string{}
	filepath.Walk(".", func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() {
			fileList = append(fileList, path)
		}
		return nil
	})

	for _, file := range fileList {
		testFile(t, file)
	}
}

var appendTests = []struct {
	startSequence uint32
	datasize      int
	parts         int
}{
	{startSequence: 0, datasize: 512 * 1024, parts: 4},
	{startSequence: 7, datasize: 64 * 1024, parts: 9},
	{startSequence: 2, datasize: 64*1024 - 1, parts: 6},
	{startSequence: 1, datasize: 64*1024 + 1, parts: 11},
	{startSequence: 33333, datasize: 1, parts: 17},
	{startSequence: 0, datasize: 64*1024 + 17, parts: 2},
	{startSequence: 5, datasize: 64*1024 - 100, parts: 4},
}

func TestAppending(t *testing.T) {
	for i, test := range appendTests {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			t.Fatalf("Failed to generate random key: %v", err)
		}
		data := make([]byte, test.datasize)
		if _, err := io.ReadFull(rand.Reader, data); err != nil {
			t.Fatalf("Failed to generate random data: %v", err)
		}

		dst := bytes.NewBuffer(nil)
		config := Config{
			Key:            key,
			SequenceNumber: test.startSequence,
		}
		for j := 0; j < test.parts; j++ {
			if _, err := Encrypt(dst, bytes.NewReader(data), config); err != nil {
				t.Fatalf("Test %d: Failed to encrypt %d part: %v", i, j, err)
			}
			config.SequenceNumber += uint32(test.datasize / maxPayloadSize)
			if test.datasize%maxPayloadSize > 0 {
				config.SequenceNumber++
			}
		}
		if _, err := Decrypt(bytes.NewBuffer(nil), bytes.NewReader(dst.Bytes()), Config{Key: key, SequenceNumber: test.startSequence}); err != nil {
			t.Errorf("Test %d: Failed to decrypt concatenated data: %v", i, err)
		}
	}
}

type devNull struct{ zero [8 * 1024]byte }

func (r *devNull) Read(p []byte) (n int, err error) {
	if len(p) < len(r.zero) {
		n = copy(p, r.zero[:len(p)])
		return
	}
	for len(p) >= len(r.zero) {
		n += copy(p, r.zero[:])
		p = p[len(r.zero):]
	}
	if len(p) > 0 {
		n += copy(p, r.zero[:len(p)])
	}
	return
}

func TestLargeStream(t *testing.T) {
	if !testing.Short() {
		t.Skip("Skipping TestLargeStream")
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	config := Config{Key: key}

	encReader, err := EncryptReader(new(devNull), config)
	if err != nil {
		t.Fatalf("Failed to create encrypted reader %v", err)
	}
	decReader, err := DecryptReader(encReader, config)
	if err != nil {
		t.Fatalf("Failed to create decrypted reader %v", err)
	}
	decWriter, err := DecryptWriter(ioutil.Discard, config)
	if err != nil {
		t.Fatalf("Failed to create decrypted writer %v", err)
	}
	encWriter, err := EncryptWriter(decWriter, config)
	if err != nil {
		t.Fatalf("Failed to create encrypted writer %v", err)
	}

	const streamsize = 50 * 1024 * 1024 * 1024
	buffer := make([]byte, 1024*1024+1)
	if _, err := io.CopyBuffer(encWriter, io.LimitReader(decReader, streamsize), buffer); err != nil {
		t.Errorf("Failed to copy data: %v", err)
	}
	if err = encWriter.Close(); err != nil {
		t.Errorf("Failed to close encrypted writer: %v", err)
	}
}

// Benchmarks

func BenchmarkEncryptReader_8KB(b *testing.B)   { benchmarkEncryptRead(1024, b) }
func BenchmarkEncryptReader_64KB(b *testing.B)  { benchmarkEncryptRead(64*1024, b) }
func BenchmarkEncryptReader_512KB(b *testing.B) { benchmarkEncryptRead(512*1024, b) }
func BenchmarkEncryptReader_1MB(b *testing.B)   { benchmarkEncryptRead(1024*1024, b) }

func BenchmarkDecryptReader_8KB(b *testing.B)   { benchmarkDecryptRead(1024, b) }
func BenchmarkDecryptReader_64KB(b *testing.B)  { benchmarkDecryptRead(64*1024, b) }
func BenchmarkDecryptReader_512KB(b *testing.B) { benchmarkDecryptRead(512*1024, b) }
func BenchmarkDecryptReader_1MB(b *testing.B)   { benchmarkDecryptRead(1024*1024, b) }

func BenchmarkEncryptWriter_8KB(b *testing.B)   { benchmarkEncryptWrite(1024, b) }
func BenchmarkEncryptWriter_64KB(b *testing.B)  { benchmarkEncryptWrite(64*1024, b) }
func BenchmarkEncryptWriter_512KB(b *testing.B) { benchmarkEncryptWrite(512*1024, b) }
func BenchmarkEncryptWriter_1MB(b *testing.B)   { benchmarkEncryptWrite(1024*1024, b) }

func BenchmarkDecryptWriter_8KB(b *testing.B)   { benchmarkDecryptWrite(1024, b) }
func BenchmarkDecryptWriter_64KB(b *testing.B)  { benchmarkDecryptWrite(64*1024, b) }
func BenchmarkDecryptWriter_512KB(b *testing.B) { benchmarkDecryptWrite(512*1024, b) }
func BenchmarkDecryptWriter_1MB(b *testing.B)   { benchmarkDecryptWrite(1024*1024, b) }

func benchmarkEncryptRead(size int64, b *testing.B) {
	data := make([]byte, size)
	buffer := make([]byte, 32+size*(size/(64*1024)+32))
	config := Config{Key: make([]byte, 32)}
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader, err := EncryptReader(bytes.NewReader(data), config)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(reader, buffer); err != nil && err != io.ErrUnexpectedEOF {
			b.Fatal(err)
		}
	}
}

func benchmarkDecryptRead(size int64, b *testing.B) {
	data := make([]byte, size)
	config := Config{Key: make([]byte, 32)}
	encrypted := bytes.NewBuffer(nil)
	encWriter, err := EncryptWriter(encrypted, config)
	if err != nil {
		b.Fatalf("Failed to create encrypted writer: %v", err)
	}
	if _, err := encWriter.Write(data); err != nil {
		b.Fatalf("Failed to write encrypted data: %v", err)
	}
	if err := encWriter.Close(); err != nil {
		b.Fatalf("Failed to close encrypted writer: %v", err)
	}

	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader, err := DecryptReader(bytes.NewReader(encrypted.Bytes()), config)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(reader, data); err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}

func benchmarkEncryptWrite(size int64, b *testing.B) {
	data := make([]byte, size)
	buffer := make([]byte, 32+size*(size/(64*1024)+32))
	config := Config{Key: make([]byte, 32)}
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptWriter, err := EncryptWriter(bytes.NewBuffer(buffer[:0]), config)
		if err != nil {
			b.Fatal(err)
		}
		if _, err = encryptWriter.Write(data); err != nil {
			b.Fatal(err)
		}
		if err = encryptWriter.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkDecryptWrite(size int64, b *testing.B) {
	data := make([]byte, size)
	config := Config{Key: make([]byte, 32)}
	encrypted := bytes.NewBuffer(nil)
	encWriter, err := EncryptWriter(encrypted, config)
	if err != nil {
		b.Fatalf("Failed to create encrypted writer: %v", err)
	}
	if _, err := encWriter.Write(data); err != nil {
		b.Fatalf("Failed to write encrypted data: %v", err)
	}
	if err := encWriter.Close(); err != nil {
		b.Fatalf("Failed to close encrypted writer: %v", err)
	}

	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decryptWriter, err := DecryptWriter(bytes.NewBuffer(data[:0]), config)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := decryptWriter.Write(encrypted.Bytes()); err != nil {
			b.Fatal(err)
		}
		if err := decryptWriter.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
