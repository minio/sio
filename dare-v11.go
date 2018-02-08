package sio

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
)

const (
	headerSizeV11     = 16
	tagSizeV11        = 16
	maxPayloadSizeV11 = 1 << 16
	maxPackageSizeV11 = headerSizeV11 + maxPayloadSizeV11 + tagSizeV11
)

func encryptWriterV11(dst io.Writer, config *Config) (io.WriteCloser, error) {
	cipher, err := supportedCiphers[config.CipherSuites[0]](config.Key)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	if _, err = io.ReadFull(config.Rand, nonce[:]); err != nil {
		return nil, err
	}
	nonce[0] &= 0x7F
	return &encryptedWriterV11{
		dst:            dst,
		cipherID:       config.CipherSuites[0],
		randVal:        nonce,
		cipher:         cipher,
		sequenceNumber: config.SequenceNumber,
	}, nil
}

func decryptWriterV11(dst io.Writer, config *Config) (io.WriteCloser, error) {
	var ciphers [2]cipher.AEAD
	for _, v := range config.CipherSuites {
		aeadCipher, err := supportedCiphers[v](config.Key)
		if err != nil {
			return nil, err
		}
		ciphers[v] = aeadCipher
	}
	var nonce [12]byte
	if _, err := io.ReadFull(config.Rand, nonce[:]); err != nil {
		return nil, err
	}
	nonce[0] &= 0x7F
	return &decryptedWriterV11{
		dst:            dst,
		ciphers:        ciphers,
		sequenceNumber: config.SequenceNumber,
	}, nil
}

type headerV11 []byte

func (h headerV11) Version() byte         { return h[0] }
func (h headerV11) SetVersion()           { h[0] = 0x11 }
func (h headerV11) Cipher() byte          { return h[1] }
func (h headerV11) SetCipher(cipher byte) { h[1] = cipher }
func (h headerV11) Length() int           { return int(binary.LittleEndian.Uint16(h[2:4])) + 1 }
func (h headerV11) SetLength(length int)  { binary.LittleEndian.PutUint16(h[2:4], uint16(length-1)) }
func (h headerV11) IsFinal() bool         { return h[4]&0x80 == 0x80 }
func (h headerV11) Nonce() []byte         { return h[4:16] }
func (h headerV11) AddData() []byte       { return h[:4] }
func (h headerV11) SetRand(randVal []byte, final bool) {
	copy(h[4:], randVal)
	if final {
		h[4] |= 0x80
	} else {
		h[4] &= 0x7F
	}
}

type packageV11 []byte

func (p packageV11) Header() headerV11  { return headerV11(p[:16]) }
func (p packageV11) Payload() []byte    { return p[16 : 16+p.Header().Length()] }
func (p packageV11) Ciphertext() []byte { return p[16 : 32+p.Header().Length()] }
