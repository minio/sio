package sio

import (
	"encoding/binary"
	"errors"
	"io"
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
	ae, err := newAuthEncV10(config)
	if err != nil {
		return nil, err
	}
	return &encReaderV1{
		authEncV10:  ae,
		src:         src,
		buffer:      make(packageV10, headerSize+maxPayloadSize+tagSize),
		payloadSize: config.PayloadSize,
	}, nil
}

func decryptReaderV10(src io.Reader, config *Config) (io.Reader, error) {
	ad, err := newAuthDecV10(config)
	if err != nil {
		return nil, err
	}
	return &decReaderV1{
		authDecV10: ad,
		src:        src,
		buffer:     make(packageV10, headerSize+maxPayloadSize+tagSize),
	}, nil
}

func encryptWriterV10(dst io.Writer, config *Config) (io.WriteCloser, error) {
	ae, err := newAuthEncV10(config)
	if err != nil {
		return nil, err
	}
	return &encWriterV1{
		authEncV10:  ae,
		dst:         dst,
		buffer:      make(packageV10, headerSize+maxPayloadSize+tagSize),
		payloadSize: config.PayloadSize,
	}, nil
}

func decryptWriterV10(dst io.Writer, config *Config) (io.WriteCloser, error) {
	ad, err := newAuthDecV10(config)
	if err != nil {
		return nil, err
	}
	return &decWriterV1{
		authDecV10: ad,
		dst:        dst,
		buffer:     make(packageV10, headerSize+maxPayloadSize+tagSize),
	}, nil
}

type headerV10 []byte

func (h headerV10) Version() byte                { return h[0] }
func (h headerV10) Cipher() byte                 { return h[1] }
func (h headerV10) Len() int                     { return int(binary.LittleEndian.Uint16(h[2:])) + 1 }
func (h headerV10) SequenceNumber() uint32       { return binary.LittleEndian.Uint32(h[4:]) }
func (h headerV10) SetVersion()                  { h[0] = Version10 }
func (h headerV10) SetCipher(suite byte)         { h[1] = suite }
func (h headerV10) SetLen(length int)            { binary.LittleEndian.PutUint16(h[2:], uint16(length-1)) }
func (h headerV10) SetSequenceNumber(num uint32) { binary.LittleEndian.PutUint32(h[4:], num) }
func (h headerV10) SetNonce(nonce []byte)        { copy(h[8:headerSize], nonce[:]) }

type packageV10 []byte

func (p packageV10) Header() headerV10  { return headerV10(p[:headerSize]) }
func (p packageV10) Payload() []byte    { return p[headerSize : p.Length()-tagSize] }
func (p packageV10) Ciphertext() []byte { return p[headerSize:p.Length()] }
func (p packageV10) Length() int        { return headerSize + tagSize + p.Header().Len() }
