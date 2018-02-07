package sio

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

const (
	headerSizeV10     = 16
	maxPayloadSizeV10 = 64 * 1024
	tagSizeV10        = 16
)

var (
	errMissingHeader      = errors.New("sio: incomplete header")
	errPayloadTooShort    = errors.New("sio: payload too short")
	errPackageOutOfOrder  = errors.New("sio: sequence number mismatch")
	errTagMismatch        = errors.New("sio: authentication failed")
	errUnsupportedVersion = errors.New("sio: unsupported version")
	errUnsupportedCipher  = errors.New("sio: unsupported cipher suite")
)

func encryptReaderV10(src io.Reader, config *Config) (io.Reader, error) {
	cipher, err := supportedCiphers[config.CipherSuites[0]](config.Key)
	if err != nil {
		return nil, err
	}
	var nonce [8]byte
	if _, err = io.ReadFull(config.Rand, nonce[:]); err != nil {
		return nil, err
	}
	return &encryptedReaderV10{
		src:            src,
		cipherID:       config.CipherSuites[0],
		nonce:          nonce,
		cipher:         cipher,
		sequenceNumber: config.SequenceNumber,
		payloadSize:    config.PayloadSize,
	}, nil
}

func decryptReaderV10(src io.Reader, config *Config) (io.Reader, error) {
	var ciphers [2]cipher.AEAD
	for _, v := range config.CipherSuites {
		aeadCipher, err := supportedCiphers[v](config.Key)
		if err != nil {
			return nil, err
		}
		ciphers[v] = aeadCipher
	}
	return &decryptedReaderV10{
		src:            src,
		ciphers:        ciphers,
		sequenceNumber: config.SequenceNumber,
	}, nil
}

func encryptWriterV10(dst io.Writer, config *Config) (io.WriteCloser, error) {
	cipher, err := supportedCiphers[config.CipherSuites[0]](config.Key)
	if err != nil {
		return nil, err
	}
	var nonce [8]byte
	if _, err = io.ReadFull(config.Rand, nonce[:]); err != nil {
		return nil, err
	}
	return &encryptedWriterV10{
		dst:            dst,
		cipherID:       config.CipherSuites[0],
		nonce:          nonce,
		cipher:         cipher,
		sequenceNumber: config.SequenceNumber,
		payloadSize:    config.PayloadSize,
	}, nil
}

func decryptWriterV10(dst io.Writer, config *Config) (io.WriteCloser, error) {
	var ciphers [2]cipher.AEAD
	for _, v := range config.CipherSuites {
		aeadCipher, err := supportedCiphers[v](config.Key)
		if err != nil {
			return nil, err
		}
		ciphers[v] = aeadCipher
	}
	return &decryptedWriterV10{
		dst:            dst,
		ciphers:        ciphers,
		sequenceNumber: config.SequenceNumber,
	}, nil
}

type headerV10 []byte

func header(b []byte) headerV10 { return headerV10(b[:headerSizeV10]) }

func (h headerV10) Version() byte { return h[0] }

func (h headerV10) Cipher() byte { return h[1] }

func (h headerV10) Len() int { return int(binary.LittleEndian.Uint16(h[2:])) + 1 }

func (h headerV10) SequenceNumber() uint32 { return binary.LittleEndian.Uint32(h[4:]) }

func (h headerV10) SetVersion() { h[0] = Version10 }

func (h headerV10) SetCipher(suite byte) { h[1] = suite }

func (h headerV10) SetLen(length int) { binary.LittleEndian.PutUint16(h[2:], uint16(length-1)) }

func (h headerV10) SetSequenceNumber(num uint32) { binary.LittleEndian.PutUint32(h[4:], num) }

func (h headerV10) SetNonce(nonce [8]byte) { copy(h[8:], nonce[:]) }
