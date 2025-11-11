// Copyright (C) 2018 Minio Inc.
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
	"os"
	"path/filepath"
	"testing"
)

var versions = []byte{0, Version10, Version20} // 0 means version not set

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

func TestEncrypt(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	config := Config{Key: key}
	for _, version := range versions {
		config.MinVersion, config.MaxVersion = version, version
		for i, test := range ioTests {
			data := make([]byte, test.datasize)
			if _, err := io.ReadFull(rand.Reader, data); err != nil {
				t.Fatalf("Version %d: Test %d: Failed to generate random data: %v", version, i, err)
			}

			decrypted, output := bytes.NewBuffer(nil), bytes.NewBuffer(nil)

			if _, err := Encrypt(output, bytes.NewReader(data), config); err != nil {
				t.Errorf("Version %d: Test %d: Encryption failed: %v", version, i, err)
			}
			// dumpDareStream(output.Bytes())
			if n, err := Decrypt(decrypted, output, config); n != int64(test.datasize) || err != nil {
				t.Errorf("Version %d: Test %d: Decryption failed: number of bytes: %d vs. %d - %v", version, i, n, test.datasize, err)
			}
			if !bytes.Equal(data, decrypted.Bytes()) {
				t.Errorf("Version %d: Test: %d: Failed to encrypt and decrypt data", version, i)
			}
		}
	}
}

func TestDecryptBuffer(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	config := Config{Key: key}

	for _, version := range versions {
		t.Run(fmt.Sprintf("v-%x", version), func(t *testing.T) {
			config.MinVersion, config.MaxVersion = version, version
			for i, test := range ioTests {
				t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
					data := make([]byte, test.datasize)
					if _, err := io.ReadFull(rand.Reader, data); err != nil {
						t.Fatalf("Version %d: Test %d: Failed to generate random data: %v", version, i, err)
					}

					output := bytes.NewBuffer(nil)

					if _, err := Encrypt(output, bytes.NewReader(data), config); err != nil {
						t.Errorf("Version %d: Test %d: Encryption failed: %v", version, i, err)
					}
					// dumpDareStream(output.Bytes())
					decrypted, err := DecryptBuffer(make([]byte, 0, output.Len()), output.Bytes(), config)
					if len(decrypted) != test.datasize || err != nil {
						t.Errorf("Version %d: Test %d: Decryption failed: number of bytes: %d vs. %d - %v", version, i, len(decrypted), test.datasize, err)
						return
					}
					if !bytes.Equal(data, decrypted) {
						t.Errorf("Version %d: Test: %d: Failed to encrypt and decrypt data", version, i)
					}

					// Test with existing data.
					decrypted, err = DecryptBuffer(make([]byte, 500), output.Bytes(), config)
					if err != nil {
						t.Errorf("Version %d: Test %d: Decryption failed: number of bytes: %d vs. %d - %v", version, i, len(decrypted), test.datasize, err)
						return
					}
					if len(decrypted) != test.datasize+500 {
						t.Errorf("Version %d: Test %d: Decryption failed: number of bytes: %d vs. %d - %v", version, i, len(decrypted), test.datasize, err)
						return
					}
					if !bytes.Equal(decrypted[:500], make([]byte, 500)) {
						t.Errorf("pre-output data was modified")
						return
					}
					decrypted = decrypted[500:]
					if len(decrypted) != test.datasize {
						t.Errorf("Version %d: Test %d: Decryption failed: number of bytes: %d vs. %d - %v", version, i, len(decrypted), test.datasize, err)
						return
					}
					if !bytes.Equal(data, decrypted) {
						t.Errorf("Version %d: Test: %d: Failed to encrypt and decrypt data", version, i)
					}
				})
			}
		})
	}
}

func TestReader(t *testing.T) {
	config := Config{Key: make([]byte, 32)}
	for _, version := range versions {
		config.MinVersion, config.MaxVersion = version, version
		for i, test := range ioTests {
			t.Run(fmt.Sprintf("v%x-%d", version, test.datasize), func(t *testing.T) {
				data, buffer := make([]byte, test.datasize), make([]byte, test.buffersize)
				if _, err := io.ReadFull(rand.Reader, data); err != nil {
					t.Fatalf("Version %d: Test %d: Failed to generate random data: %v", version, i, err)
				}

				encReader, err := EncryptReader(bytes.NewReader(data), config)
				if err != nil {
					t.Fatalf("Version %d: Test %d: Failed to create encrypted reader: %v", version, i, err)
				}
				decReader, err := DecryptReader(encReader, config)
				if err != nil {
					t.Fatalf("Version %d: Test %d: Failed to create decrypted reader: %v", version, i, err)
				}

				_, err = io.ReadFull(decReader, buffer)
				if err == io.ErrUnexpectedEOF && test.buffersize < test.datasize {
					t.Errorf("Version %d: Test %d: Reading failed: %v", version, i, err)
				}
				if err != nil && err != io.ErrUnexpectedEOF {
					t.Errorf("Version %d: Test %d: Reading failed: %v", version, i, err)
				}

				if version == Version20 {
					ciphertext := bytes.NewBuffer(nil)
					encReader, err = EncryptReader(bytes.NewReader(data), config)
					if err != nil {
						t.Fatalf("Version %d: Test %d: Failed to create encrypted reader: %v", version, i, err)
					}
					if _, err = io.Copy(ciphertext, encReader); err != nil {
						t.Fatalf("Version %d: Test %d: Failed to encrypted data: %v", version, i, err)
					}

					plaintext := bytes.NewBuffer(nil)
					decReaderAt, err := DecryptReaderAt(bytes.NewReader(ciphertext.Bytes()), config)
					if err != nil {
						t.Fatalf("Version %d: Test %d: Failed to create decrypted reader: %v", version, i, err)
					}
					if _, err = io.Copy(plaintext, io.NewSectionReader(decReaderAt, 0, int64(ciphertext.Len()))); err != nil {
						t.Fatalf("Version %d: Test %d: Failed to encrypted data: %v", version, i, err)
					}
					if !bytes.Equal(data, plaintext.Bytes()) {
						t.Fatalf("Version %d: Test %d: The plaintexts do not match: %v", version, i, err)
					}
				}
			})
		}
	}
}

func TestReaderAt(t *testing.T) {
	config := Config{Key: make([]byte, 32)}
	plaintext := bytes.NewBuffer(nil)
	ciphertext := bytes.NewBuffer(nil)
	for _, version := range versions {
		config.MinVersion, config.MaxVersion = version, version
		for i, test := range ioTests {
			t.Run(fmt.Sprintf("v%x-%d", version, test.datasize), func(t *testing.T) {
				plaintext.Reset()
				ciphertext.Reset()

				data := make([]byte, test.datasize)
				encReader, err := EncryptReader(bytes.NewReader(data), config)
				if err != nil {
					t.Fatalf("Version %d: Test %d: Failed to create encrypted reader: %v", version, i, err)
				}
				if _, err = io.Copy(ciphertext, encReader); err != nil {
					t.Fatalf("Version %d: Test %d: Failed to encrypted data: %v", version, i, err)
				}

				decReaderAt, err := DecryptReaderAt(bytes.NewReader(ciphertext.Bytes()), config)
				if err != nil {
					t.Fatalf("Version %d: Test %d: Failed to create decrypted reader: %v", version, i, err)
				}
				if _, err = io.Copy(plaintext, io.NewSectionReader(decReaderAt, 0, int64(test.datasize/2))); err != nil {
					t.Fatalf("Version %d: Test %d: Failed to decrypted data: %v", version, i, err)
				}
				if _, err = io.Copy(plaintext, io.NewSectionReader(decReaderAt, int64(test.datasize/2), int64(test.datasize))); err != nil {
					t.Fatalf("Version %d: Test %d: Failed to decrypted data: %v", version, i, err)
				}
				if !bytes.Equal(data, plaintext.Bytes()) {
					t.Fatalf("Version %d: Test %d: The plaintexts do not match", version, i)
				}
			})
		}
	}
}

func TestReaderAtSection(t *testing.T) {
	config := Config{Key: make([]byte, 32)}
	plaintext := bytes.NewBuffer(nil)
	ciphertext := bytes.NewBuffer(nil)
	data := append(make([]byte, maxPackageSize), []byte("Hello World")...)
	for _, version := range versions {
		config.MinVersion, config.MaxVersion = version, version
		plaintext.Reset()
		ciphertext.Reset()

		encReader, err := EncryptReader(bytes.NewReader(data), config)
		if err != nil {
			t.Fatalf("Version %d: Failed to create encrypted reader: %v", version, err)
		}
		if _, err = io.Copy(ciphertext, encReader); err != nil {
			t.Fatalf("Version %d: Failed to encrypted data: %v", version, err)
		}

		decReaderAt, err := DecryptReaderAt(bytes.NewReader(ciphertext.Bytes()), config)
		if err != nil {
			t.Fatalf("Version %d: Failed to create decrypted reader: %v", version, err)
		}
		if _, err = io.Copy(plaintext, io.NewSectionReader(decReaderAt, maxPackageSize+6, int64(len(data)))); err != nil {
			t.Fatalf("Version %d: Failed to decrypted data: %v", version, err)
		}
		if !bytes.Equal([]byte("World"), plaintext.Bytes()) {
			t.Fatalf("Version %d: The plaintexts do not match", version)
		}
	}
}

func TestWriter(t *testing.T) {
	config := Config{Key: make([]byte, 32)}
	for _, version := range versions {
		config.MinVersion, config.MaxVersion = version, version
		for i, test := range ioTests {
			data := make([]byte, test.datasize)
			if _, err := io.ReadFull(rand.Reader, data); err != nil {
				t.Fatalf("Version %d: Test %d: Failed to generate random data: %v", version, i, err)
			}

			output := bytes.NewBuffer(nil)

			decWriter, err := DecryptWriter(output, config)
			if err != nil {
				t.Fatalf("Version %d: Test %d: Failed to create decrypted writer: %v", version, i, err)
			}
			encWriter, err := EncryptWriter(decWriter, config)
			if err != nil {
				t.Fatalf("Version %d: Test %d: Failed to create encrypted writer: %v", version, i, err)
			}

			if _, err := encWriter.Write(data[:1]); err != nil {
				t.Errorf("Version %d: Test %d: Writing failed: %v", version, i, err)
			}
			if _, err := encWriter.Write(data[1:]); err != nil {
				t.Errorf("Version %d: Test %d: Writing failed: %v", version, i, err)
			}
			if err := encWriter.Close(); err != nil {
				t.Errorf("Version %d: Test: %d: Failed to close encrypt writer: %v", version, i, err)
			}
			if err := decWriter.Close(); err != nil {
				t.Errorf("Version %d: Test: %d: Failed to close decode writer: %v", version, i, err)
			}
			if !bytes.Equal(data, output.Bytes()) {
				t.Errorf("Version %d: Test: %d: Failed to encrypt and decrypt data", version, i)
			}
		}
	}
}

func TestCopy(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	config := Config{Key: key}
	for _, version := range versions {
		config.MinVersion, config.MaxVersion = version, version
		for i, test := range ioTests {
			t.Run(fmt.Sprintf("v%x-%d", version, test.datasize), func(t *testing.T) {
				data, buffer := make([]byte, test.datasize), make([]byte, test.buffersize)
				if _, err := io.ReadFull(rand.Reader, data); err != nil {
					t.Fatalf("Version %d: Test %d: Failed to generate random data: %v", version, i, err)
				}

				output := bytes.NewBuffer(nil)

				decWriter, err := DecryptWriter(output, config)
				if err != nil {
					t.Fatalf("Version %d: Test %d: Failed to create decrypted writer: %v", version, i, err)
				}
				encReader, err := EncryptReader(bytes.NewReader(data), config)
				if err != nil {
					t.Fatalf("Version %d: Test %d: Failed to create encrypted reader: %v", version, i, err)
				}

				if _, err := io.CopyBuffer(decWriter, encReader, buffer); err != nil {
					t.Fatalf("Version %d: Test: %d: Failed to copy: %v", version, i, err)
				}
				if err := decWriter.Close(); err != nil {
					t.Fatalf("Version %d: Test: %d: Failed to close writer: %v", version, i, err)
				}
				if !bytes.Equal(data, output.Bytes()) {
					t.Fatalf("Version %d: Test: %d: Failed to encrypt and decrypt data", version, i)
				}
			})
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

	for _, version := range versions {
		for i, test := range sequenceNumberTest {
			config := Config{
				MinVersion:     version,
				MaxVersion:     version,
				Key:            key,
				SequenceNumber: test.sequence,
			}

			data := make([]byte, maxPayloadSize*test.packages)
			if _, err = io.ReadFull(rand.Reader, data); err != nil {
				t.Fatalf("Version %d: Test %d: Failed to generate random data: %v", version, i, err)
			}
			dst := make([]byte, (headerSize+maxPayloadSize+tagSize)*test.packages)
			if _, err = Encrypt(bytes.NewBuffer(dst[:0]), bytes.NewReader(data), config); err != nil {
				t.Errorf("Version %d: Test %d: Failed to encrypt data: %v", version, i, err)
			}

			if _, err = Decrypt(bytes.NewBuffer(nil), bytes.NewReader(dst), config); err != nil {
				t.Errorf("Version %d: Test %d: Failed to decrypt data: %v", version, i, err)
			}

			unmodifiedHeader := make([]byte, headerSize)
			offset := (headerSize + maxPayloadSize + tagSize) * test.modify
			header := headerV10(dst[offset : offset+headerSize])
			copy(unmodifiedHeader, header)

			header.SetSequenceNumber(test.badSequence)
			if _, err = Decrypt(bytes.NewBuffer(nil), bytes.NewReader(dst), config); err == nil {
				t.Errorf("Version %d: Test %d: Expected to report error while decrypting but decryption passed successfully", version, i)
			}

			decWriter, err := DecryptWriter(bytes.NewBuffer(nil), config)
			if err != nil {
				t.Fatalf("Version %d: Test %d: Failed to create decrypting writer: %v", version, i, err)
			}
			if _, err = io.Copy(decWriter, bytes.NewReader(dst)); err == nil {
				t.Errorf("Version %d: Test %d: Expected to report error while decrypting but decryption passed successfully", version, i)
			}
			copy(header, unmodifiedHeader)
		}
	}
}

func testFile(t *testing.T, file string) {
	data, err := os.ReadFile(file) //nolint:gosec // Test file
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
	err := filepath.Walk(".", func(path string, f os.FileInfo, _ error) error {
		if !f.IsDir() {
			fileList = append(fileList, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to walk directory: %v", err)
	}

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
			MaxVersion:     Version10, // appending only works for 1.0
			Key:            key,
			SequenceNumber: test.startSequence,
		}
		for j := 0; j < test.parts; j++ {
			if _, err := Encrypt(dst, bytes.NewReader(data), config); err != nil {
				t.Fatalf("Test %d: Failed to encrypt %d part: %v", i, j, err)
			}
			config.SequenceNumber += uint32(test.datasize / maxPayloadSize) //nolint:gosec // Test data size conversion
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
		return n, err
	}
	for len(p) >= len(r.zero) {
		n += copy(p, r.zero[:])
		p = p[len(r.zero):]
	}
	if len(p) > 0 {
		n += copy(p, r.zero[:len(p)])
	}
	return n, err
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
	decWriter, err := DecryptWriter(io.Discard, config)
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

var encryptedSizeTests = []struct {
	size, encSize uint64
	shouldFail    bool
}{
	{size: 0, encSize: 0},  // 0
	{size: 1, encSize: 33}, // 1
	{size: maxPayloadSize + 1, encSize: maxPayloadSize + 1 + 64},       // 2
	{size: 2 * maxPayloadSize, encSize: 2*maxPayloadSize + 64},         // 3
	{size: 2*maxPayloadSize + 17, encSize: 2*maxPayloadSize + 17 + 96}, // 4
	{size: maxDecryptedSize, encSize: maxEncryptedSize},                // 5
	{size: 1 + maxDecryptedSize, encSize: 0, shouldFail: true},         // 6
}

func TestEncryptedSize(t *testing.T) {
	for i, test := range encryptedSizeTests {
		size, err := EncryptedSize(test.size)
		if err != nil && !test.shouldFail {
			t.Errorf("Test %d: expected pass but failed with: %v", i, err)
		}
		if err == nil && test.shouldFail {
			t.Errorf("Test %d: expected fail but succeeded", i)
		}
		if size != test.encSize {
			t.Errorf("Test %d: got: %d want: %d", i, size, test.encSize)
		}
	}
}

var decryptedSizeTests = []struct {
	size, decSize uint64
	shouldFail    bool
}{
	{size: 0, decSize: 0},  // 0
	{size: 33, decSize: 1}, // 1
	{size: maxPayloadSize + 1 + 64, decSize: maxPayloadSize + 1},       // 2
	{size: 2*maxPayloadSize + 64, decSize: 2 * maxPayloadSize},         // 3
	{size: 2*maxPayloadSize + 17 + 96, decSize: 2*maxPayloadSize + 17}, // 4
	{size: maxEncryptedSize, decSize: maxDecryptedSize},                // 5
	{size: 1 + maxEncryptedSize, decSize: 0, shouldFail: true},         // 6
	{size: 1, decSize: 0, shouldFail: true},                            // 7
	{size: maxPackageSize + 1, decSize: 0, shouldFail: true},           // 8
}

func TestDecryptedSize(t *testing.T) {
	for i, test := range decryptedSizeTests {
		size, err := DecryptedSize(test.size)
		if err != nil && !test.shouldFail {
			t.Errorf("Test %d: expected pass but failed with: %v", i, err)
		}
		if err == nil && test.shouldFail {
			t.Errorf("Test %d: expected fail but succeeded", i)
		}
		if size != test.decSize {
			t.Errorf("Test %d: got: %d want: %d", i, size, test.decSize)
		}
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

func BenchmarkDecryptReaderAt_8KB(b *testing.B)   { benchmarkDecryptReadAt(1024, b) }
func BenchmarkDecryptReaderAt_64KB(b *testing.B)  { benchmarkDecryptReadAt(64*1024, b) }
func BenchmarkDecryptReaderAt_512KB(b *testing.B) { benchmarkDecryptReadAt(512*1024, b) }
func BenchmarkDecryptReaderAt_1MB(b *testing.B)   { benchmarkDecryptReadAt(1024*1024, b) }

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
	config := Config{Key: make([]byte, 32)}
	b.SetBytes(size)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reader, err := EncryptReader(bytes.NewReader(data), config)
			if err != nil {
				b.Fatal(err)
			}
			_, err = io.Copy(io.Discard, reader)
			if err != nil && err != io.ErrUnexpectedEOF {
				b.Fatal(err)
			}
		}
	})
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
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reader, err := DecryptReader(bytes.NewReader(encrypted.Bytes()), config)
			if err != nil {
				b.Fatal(err)
			}
			_, err = io.Copy(io.Discard, reader)
			if err != nil && err != io.EOF {
				b.Fatal(err)
			}
		}
	})
}

func benchmarkDecryptReadAt(size int64, b *testing.B) {
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
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		data := make([]byte, size)
		for pb.Next() {
			reader, err := DecryptReaderAt(bytes.NewReader(encrypted.Bytes()), config)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := reader.ReadAt(data[:len(data)/2], 0); err != nil && err != io.EOF {
				b.Fatal(err)
			}
			if _, err := reader.ReadAt(data[len(data)/2:], int64(len(data)/2)); err != nil && err != io.EOF {
				b.Fatal(err)
			}
		}
	})
}

func benchmarkEncryptWrite(size int64, b *testing.B) {
	data := make([]byte, size)
	config := Config{Key: make([]byte, 32)}
	b.SetBytes(size)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		buffer := make([]byte, 32+size*(size/(64*1024)+32))
		for pb.Next() {
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
	})
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
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		data := make([]byte, size)
		for pb.Next() {
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
	})
}
