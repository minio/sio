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
	"crypto/cipher"
	"encoding/binary"
	"io"
)

type authEnc struct {
	CipherID byte
	SeqNum   uint32
	Cipher   cipher.AEAD
	RandVal  []byte
}

type authDec struct {
	SeqNum  uint32
	Ciphers [2]cipher.AEAD
}

type authEncV10 authEnc

func newAuthEncV10(cfg *Config) (authEncV10, error) {
	cipherID := cfg.CipherSuites[0]
	cipher, err := supportedCiphers[cipherID](cfg.Key)
	if err != nil {
		return authEncV10{}, err
	}
	var randVal [8]byte
	if _, err = io.ReadFull(cfg.Rand, randVal[:]); err != nil {
		return authEncV10{}, err
	}
	return authEncV10{
		CipherID: cipherID,
		RandVal:  randVal[:],
		Cipher:   cipher,
		SeqNum:   cfg.SequenceNumber,
	}, nil
}

func (ae *authEncV10) Seal(dst, src []byte) {
	header := headerV10(dst[:headerSize])
	header.SetVersion()
	header.SetCipher(ae.CipherID)
	header.SetLen(len(src))
	header.SetSequenceNumber(ae.SeqNum)
	header.SetNonce(ae.RandVal)
	ae.Cipher.Seal(dst[headerSize:headerSize], header[4:headerSize], src, header[:4])
	ae.SeqNum++
}

type authDecV10 authDec

func newAuthDecV10(cfg *Config) (authDecV10, error) {
	var ciphers [2]cipher.AEAD
	for _, v := range cfg.CipherSuites {
		aeadCipher, err := supportedCiphers[v](cfg.Key)
		if err != nil {
			return authDecV10{}, err
		}
		ciphers[v] = aeadCipher
	}
	return authDecV10{
		SeqNum:  cfg.SequenceNumber,
		Ciphers: ciphers,
	}, nil
}

func (ad *authDecV10) Open(dst, src []byte) error {
	header := headerV10(src[:headerSize])
	if header.Version() != Version10 {
		return errUnsupportedVersion
	}
	if header.Cipher() > CHACHA20_POLY1305 {
		return errUnsupportedCipher
	}
	aeadCipher := ad.Ciphers[header.Cipher()]
	if aeadCipher == nil {
		return errUnsupportedCipher
	}
	if headerSize+header.Len()+tagSize != len(src) {
		return errPayloadTooShort
	}
	if header.SequenceNumber() != ad.SeqNum {
		return errPackageOutOfOrder
	}
	ciphertext := src[headerSize : headerSize+header.Len()+tagSize]
	if _, err := aeadCipher.Open(dst[:0], header[4:headerSize], ciphertext, header[:4]); err != nil {
		return errTagMismatch
	}
	ad.SeqNum++
	return nil
}

type authEncV20 authEnc

func (ae *authEncV20) Seal(dst, src []byte)      { ae.seal(dst, src, false) }
func (ae *authEncV20) SealFinal(dst, src []byte) { ae.seal(dst, src, true) }

func (ae *authEncV20) seal(dst, src []byte, finalize bool) {
	var nonce [12]byte
	copy(nonce[:8], ae.RandVal[:8])
	binary.LittleEndian.PutUint32(nonce[8:], binary.LittleEndian.Uint32(ae.RandVal[8:])^ae.SeqNum)

	header := headerV11(dst[:headerSizeV11])
	header.SetVersion()
	header.SetCipher(ae.CipherID)
	header.SetLength(len(src))
	header.SetRand(nonce[:], finalize)
	ae.Cipher.Seal(dst[headerSizeV11:headerSizeV11], header.Nonce(), src, header.AddData())
	ae.SeqNum++
}
