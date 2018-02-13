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
	"crypto/cipher"
	"io"
)

type encryptedReaderV10 struct {
	src io.Reader

	cipherID       byte
	sequenceNumber uint32
	nonce          [8]byte
	cipher         cipher.AEAD

	pack        [headerSizeV10 + maxPayloadSizeV10 + tagSizeV10]byte
	payloadSize int
	offset      int
}

func (r *encryptedReaderV10) Read(p []byte) (n int, err error) {
	if r.offset > 0 {
		remaining := headerSizeV10 + header(r.pack[:]).Len() + tagSizeV10 - r.offset
		if len(p) < remaining {
			n = copy(p, r.pack[r.offset:r.offset+len(p)])
			r.offset += n
			return
		}
		n = copy(p, r.pack[r.offset:r.offset+remaining])
		p = p[remaining:]
		r.offset = 0
	}
	for len(p) >= headerSizeV10+r.payloadSize+tagSizeV10 {
		nn, err := io.ReadFull(r.src, r.pack[headerSizeV10:headerSizeV10+r.payloadSize])
		if err != nil && err != io.ErrUnexpectedEOF {
			return n, err
		}
		r.encrypt(p, nn)
		n += headerSizeV10 + nn + tagSizeV10
		p = p[headerSizeV10+nn+tagSizeV10:]
	}
	if len(p) > 0 {
		nn, err := io.ReadFull(r.src, r.pack[headerSizeV10:headerSizeV10+r.payloadSize])
		if err != nil && err != io.ErrUnexpectedEOF {
			return n, err
		}
		r.encrypt(r.pack[:], nn)
		if headerSizeV10+nn+tagSizeV10 < len(p) {
			r.offset = copy(p, r.pack[:headerSizeV10+nn+tagSizeV10])
		} else {
			r.offset = copy(p, r.pack[:len(p)])
		}
		n += r.offset
	}
	return
}

func (r *encryptedReaderV10) encrypt(dst []byte, length int) {
	header := header(dst)
	header.SetVersion()
	header.SetCipher(r.cipherID)
	header.SetLen(length)
	header.SetSequenceNumber(r.sequenceNumber)
	header.SetNonce(r.nonce)

	copy(dst[:headerSizeV10], header)
	r.cipher.Seal(dst[headerSizeV10:headerSizeV10], header[4:headerSizeV10], r.pack[headerSizeV10:headerSizeV10+length], header[:4])

	r.sequenceNumber++
}

type decryptedReaderV10 struct {
	src io.Reader

	sequenceNumber uint32
	ciphers        [2]cipher.AEAD

	pack   [headerSizeV10 + maxPayloadSizeV10 + tagSizeV10]byte
	offset int
}

func (r *decryptedReaderV10) Read(p []byte) (n int, err error) {
	if r.offset > 0 {
		remaining := header(r.pack[:]).Len() - r.offset
		if len(p) < remaining {
			n = copy(p, r.pack[headerSizeV10+r.offset:headerSizeV10+r.offset+len(p)])
			r.offset += n
			return
		}
		n = copy(p, r.pack[headerSizeV10+r.offset:headerSizeV10+r.offset+remaining])
		p = p[remaining:]
		r.offset = 0
	}
	for len(p) >= maxPayloadSizeV10 {
		if err = r.readHeader(); err != nil {
			return n, err
		}
		nn, err := r.decrypt(p[:maxPayloadSizeV10])
		if err != nil {
			return n, err
		}
		p = p[nn:]
		n += nn
	}
	if len(p) > 0 {
		if err = r.readHeader(); err != nil {
			return n, err
		}
		nn, err := r.decrypt(r.pack[headerSizeV10:])
		if err != nil {
			return n, err
		}
		if nn < len(p) {
			r.offset = copy(p, r.pack[headerSizeV10:headerSizeV10+nn])
		} else {
			r.offset = copy(p, r.pack[headerSizeV10:headerSizeV10+len(p)])
		}
		n += r.offset
	}
	return
}

func (r *decryptedReaderV10) readHeader() error {
	n, err := io.ReadFull(r.src, header(r.pack[:]))
	if n != headerSizeV10 && err == io.ErrUnexpectedEOF {
		return errMissingHeader
	} else if err != nil {
		return err
	}
	return nil
}

func (r *decryptedReaderV10) decrypt(dst []byte) (n int, err error) {
	header := header(r.pack[:])
	if header.Version() != Version10 {
		return 0, errUnsupportedVersion
	}
	if header.Cipher() > CHACHA20_POLY1305 {
		return 0, errUnsupportedCipher
	}
	aeadCipher := r.ciphers[header.Cipher()]
	if aeadCipher == nil {
		return 0, errUnsupportedCipher
	}
	if header.SequenceNumber() != r.sequenceNumber {
		return 0, errPackageOutOfOrder
	}
	ciphertext := r.pack[headerSizeV10 : headerSizeV10+header.Len()+tagSizeV10]
	n, err = io.ReadFull(r.src, ciphertext)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return 0, errPayloadTooShort
	} else if err != nil {
		return 0, err
	}
	plaintext, err := aeadCipher.Open(dst[:0], header[4:], ciphertext, header[:4])
	if err != nil {
		return 0, errTagMismatch
	}
	r.sequenceNumber++
	return len(plaintext), nil
}
