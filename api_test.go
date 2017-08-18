package aead

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

var ioTests = []struct {
	datasize, buffersize int
}{
	{datasize: 1, buffersize: 1},                                        // 0
	{datasize: 2, buffersize: 1},                                        // 1
	{datasize: payloadSize - 1, buffersize: 1},                          // 2
	{datasize: payloadSize, buffersize: 1},                              // 3
	{datasize: payloadSize + 1, buffersize: 1},                          // 4
	{datasize: 1, buffersize: headerSize},                               // 5
	{datasize: 1024, buffersize: headerSize},                            // 6
	{datasize: payloadSize - 1, buffersize: headerSize},                 // 7
	{datasize: payloadSize, buffersize: headerSize},                     // 8
	{datasize: payloadSize + 1, buffersize: headerSize},                 // 9
	{datasize: 1, buffersize: payloadSize},                              // 10
	{datasize: 32 * 1024, buffersize: payloadSize},                      // 11
	{datasize: payloadSize - 1, buffersize: payloadSize},                // 12
	{datasize: payloadSize, buffersize: payloadSize},                    // 13
	{datasize: payloadSize + 1, buffersize: payloadSize},                // 14
	{datasize: 1, buffersize: payloadSize + tagSize},                    // 15
	{datasize: 7 * 1024, buffersize: payloadSize + tagSize},             // 16
	{datasize: payloadSize - 1, buffersize: payloadSize + tagSize},      // 17
	{datasize: payloadSize, buffersize: payloadSize + tagSize},          // 18
	{datasize: payloadSize + 1, buffersize: payloadSize + tagSize},      // 19
	{datasize: 1, buffersize: headerSize + payloadSize + tagSize},       // 20
	{datasize: 2 * payloadSize, buffersize: payloadSize + tagSize},      // 21
	{datasize: 2*payloadSize - 1, buffersize: payloadSize + tagSize},    // 22
	{datasize: 2*payloadSize + 1, buffersize: payloadSize + tagSize},    // 23
	{datasize: 2*payloadSize + 1024, buffersize: payloadSize + tagSize}, // 24
	{datasize: 1, buffersize: payloadSize + 1},                          // 25
	{datasize: 2 * payloadSize, buffersize: payloadSize + 1},            // 26
	{datasize: 1024*1024 - 1, buffersize: payloadSize + 1},              // 27
	{datasize: 1024 * 1024, buffersize: payloadSize + 1},                // 28
	{datasize: 1024*1024 + 1, buffersize: payloadSize + 1},              // 29
	{datasize: 2 * payloadSize, buffersize: 1024 * 1024},                // 30
	{datasize: 3*payloadSize + 1, buffersize: 3 * payloadSize},          // 31
	{datasize: 1024 * 1024, buffersize: 2 * 1024 * 1024},                // 32
	{datasize: payloadSize + 1, buffersize: payloadSize - 1},            // 33
}

func TestEncrypt(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	config := Config{Key: key}
	for i, test := range ioTests[:1] {
		data := make([]byte, test.datasize)
		decrypted, output := bytes.NewBuffer(nil), bytes.NewBuffer(nil)

		if _, err := Encrypt(output, bytes.NewReader(data), config); err != nil {
			t.Errorf("Test %d: Encryption failed: %v", i, err)
		}
		if n, err := Decrypt(decrypted, output, config); n != int64(test.datasize) || err != nil {
			t.Errorf("Test %d: Decryption failed: number of bytes: %d - %v", i, n, err)
		}
		if !bytes.Equal(data, decrypted.Bytes()) {
			t.Errorf("Test: %d: Failed to encrypt and decrypt data. %v | %v", i, data, decrypted.Bytes())
		}
	}
}

func TestReader(t *testing.T) {
	config := Config{Key: make([]byte, 32)}
	for i, test := range ioTests {
		data, buffer := make([]byte, test.datasize), make([]byte, test.buffersize)

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
		output := bytes.NewBuffer(nil)

		decWriter, err := DecryptWriter(output, config)
		if err != nil {
			t.Fatalf("Test %d: Failed to create decrypted writer: %v", i, err)
		}
		encWriter, err := EncryptWriter(decWriter, config)
		if err != nil {
			t.Fatalf("Test %d: Failed to create encrypted writer: %v", i, err)
		}

		if _, err := encWriter.Write(data); err != nil {
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
		data:       make([]byte, payloadSize),
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
		data:       make([]byte, payloadSize),
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

// Benchmarks

func BenchmarkEncryptReader_8KB(b *testing.B)  { benchmarkEncryptRead(1024, b) }
func BenchmarkEncryptReader_64KB(b *testing.B) { benchmarkEncryptRead(64*1024, b) }
func BenchmarkEncryptReader_1MB(b *testing.B)  { benchmarkEncryptRead(1024*1024, b) }
func BenchmarkEncryptReader_5MB(b *testing.B)  { benchmarkEncryptRead(1024*1024, b) }

func BenchmarkDecryptReader_8KB(b *testing.B)  { benchmarkDecryptRead(1024, b) }
func BenchmarkDecryptReader_64KB(b *testing.B) { benchmarkDecryptRead(64*1024, b) }
func BenchmarkDecryptReader_1MB(b *testing.B)  { benchmarkDecryptRead(1024*1024, b) }
func BenchmarkDecryptReader_5MB(b *testing.B)  { benchmarkDecryptRead(1024*1024, b) }

func BenchmarkEncryptWriter_8KB(b *testing.B)  { benchmarkEncryptWrite(1024, b) }
func BenchmarkEncryptWriter_64KB(b *testing.B) { benchmarkEncryptWrite(64*1024, b) }
func BenchmarkEncryptWriter_1MB(b *testing.B)  { benchmarkEncryptWrite(1024*1024, b) }
func BenchmarkEncryptWriter_5MB(b *testing.B)  { benchmarkEncryptWrite(1024*1024, b) }

func BenchmarkDecryptWriter_8KB(b *testing.B)  { benchmarkDecryptWrite(1024, b) }
func BenchmarkDecryptWriter_64KB(b *testing.B) { benchmarkDecryptWrite(64*1024, b) }
func BenchmarkDecryptWriter_1MB(b *testing.B)  { benchmarkDecryptWrite(1024*1024, b) }
func BenchmarkDecryptWriter_5MB(b *testing.B)  { benchmarkDecryptWrite(1024*1024, b) }

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
