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

type decryptedWriterV10 struct {
	dst io.Writer

	sequenceNumber uint32
	ciphers        [2]cipher.AEAD

	pack   [headerSizeV10 + maxPayloadSizeV10 + tagSizeV10]byte
	offset int
}

func (w *decryptedWriterV10) Write(p []byte) (n int, err error) {
	if w.offset > 0 && w.offset < headerSizeV10 {
		remaining := headerSizeV10 - w.offset
		if len(p) < remaining {
			n = copy(w.pack[w.offset:], p)
			w.offset += n
			return
		}
		n = copy(w.pack[w.offset:], p[:remaining])
		p = p[remaining:]
		w.offset += n
	}
	if w.offset >= headerSizeV10 {
		remaining := headerSizeV10 + header(w.pack[:]).Len() + tagSizeV10 - w.offset
		if len(p) < remaining {
			nn := copy(w.pack[w.offset:], p)
			w.offset += nn
			return n + nn, err
		}
		n += copy(w.pack[w.offset:], p[:remaining])
		if err = w.decrypt(w.pack[:]); err != nil {
			return n, err
		}
		p = p[remaining:]
		w.offset = 0
	}
	for len(p) > headerSizeV10 {
		header := header(p)
		if len(p) < headerSizeV10+header.Len()+tagSizeV10 {
			w.offset = copy(w.pack[:], p)
			n += w.offset
			return
		}
		if err = w.decrypt(p); err != nil {
			return n, err
		}
		p = p[headerSizeV10+header.Len()+tagSizeV10:]
		n += headerSizeV10 + header.Len() + tagSizeV10
	}
	w.offset = copy(w.pack[:], p)
	n += w.offset
	return
}

func (w *decryptedWriterV10) Close() error {
	if w.offset > 0 {
		if w.offset < headerSizeV10 {
			return errMissingHeader
		}
		if w.offset < headerSizeV10+header(w.pack[:]).Len()+tagSizeV10 {
			return errPayloadTooShort
		}
		if err := w.decrypt(w.pack[:]); err != nil {
			return err
		}
	}
	if dst, ok := w.dst.(io.Closer); ok {
		return dst.Close()
	}
	return nil
}

func (w *decryptedWriterV10) decrypt(src []byte) error {
	header := header(src)
	if header.Version() != Version10 {
		return errUnsupportedVersion
	}
	if header.Cipher() > CHACHA20_POLY1305 {
		return errUnsupportedCipher
	}
	aeadCipher := w.ciphers[header.Cipher()]
	if aeadCipher == nil {
		return errUnsupportedCipher
	}
	if header.SequenceNumber() != w.sequenceNumber {
		return errPackageOutOfOrder
	}

	plaintext, err := aeadCipher.Open(w.pack[headerSizeV10:headerSizeV10], header[4:headerSizeV10], src[headerSizeV10:headerSizeV10+header.Len()+tagSizeV10], header[:4])
	if err != nil {
		return errTagMismatch
	}

	n, err := w.dst.Write(plaintext)
	if err != nil {
		return err
	}
	if n != len(plaintext) {
		return io.ErrShortWrite
	}

	w.sequenceNumber++
	return nil
}

type encryptedWriterV10 struct {
	dst io.Writer

	cipherID       byte
	nonce          [8]byte
	sequenceNumber uint32
	cipher         cipher.AEAD

	pack        [headerSizeV10 + maxPayloadSizeV10 + tagSizeV10]byte
	payloadSize int
	offset      int
}

func (w *encryptedWriterV10) Write(p []byte) (n int, err error) {
	if w.offset > 0 {
		remaining := w.payloadSize - w.offset
		if len(p) < remaining {
			n = copy(w.pack[headerSizeV10+w.offset:], p)
			w.offset += n
			return
		}
		n = copy(w.pack[headerSizeV10+w.offset:], p[:remaining])
		if err = w.encrypt(w.pack[headerSizeV10 : headerSizeV10+w.payloadSize]); err != nil {
			return
		}
		p = p[remaining:]
		w.offset = 0
	}
	for len(p) >= w.payloadSize {
		if err = w.encrypt(p[:w.payloadSize]); err != nil {
			return
		}
		p = p[w.payloadSize:]
		n += w.payloadSize
	}
	if len(p) > 0 {
		w.offset = copy(w.pack[headerSizeV10:], p)
		n += w.offset
	}
	return
}

func (w *encryptedWriterV10) Close() error {
	if w.offset > 0 {
		return w.encrypt(w.pack[headerSizeV10 : headerSizeV10+w.offset])
	}
	if dst, ok := w.dst.(io.Closer); ok {
		return dst.Close()
	}
	return nil
}

func (w *encryptedWriterV10) encrypt(src []byte) error {
	header := header(w.pack[:])
	header.SetVersion()
	header.SetCipher(w.cipherID)
	header.SetLen(len(src))
	header.SetSequenceNumber(w.sequenceNumber)
	header.SetNonce(w.nonce)

	w.cipher.Seal(w.pack[headerSizeV10:headerSizeV10], header[4:headerSizeV10], src, header[:4])

	n, err := w.dst.Write(w.pack[:headerSizeV10+len(src)+tagSizeV10])
	if err != nil {
		return err
	}
	if n != headerSizeV10+len(src)+tagSizeV10 {
		return io.ErrShortWrite
	}

	w.sequenceNumber++
	return nil
}
