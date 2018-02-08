package sio

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
)

type encryptedWriterV11 struct {
	dst io.Writer

	cipherID       byte
	sequenceNumber uint32
	randVal        [12]byte
	cipher         cipher.AEAD

	buffer [maxPackageSizeV11]byte
	offset int
}

func (w *encryptedWriterV11) encrypt(src []byte, final bool) error {
	pack := packageV11(w.buffer[:])
	header := pack.Header()
	header.SetVersion()
	header.SetCipher(w.cipherID)
	header.SetLength(len(src))
	header.SetRand(w.randVal[:], final)

	var nonce [12]byte
	copy(nonce[:], header.Nonce())
	binary.LittleEndian.PutUint32(nonce[8:], binary.LittleEndian.Uint32(nonce[8:])^w.sequenceNumber)
	ctLen := len(w.cipher.Seal(pack.Ciphertext()[:0], nonce[:], src, header.AddData()))
	w.sequenceNumber++

	n, err := w.dst.Write(pack[:headerSizeV11+ctLen])
	if err != nil {
		return err
	}
	if n != headerSizeV11+ctLen {
		return io.ErrShortWrite
	}
	return nil
}

func (w *encryptedWriterV11) Write(p []byte) (n int, err error) {
	if w.offset > 0 {
		remaining := maxPayloadSizeV11 - w.offset
		if len(p) <= remaining {
			w.offset += copy(w.buffer[headerSizeV11+w.offset:], p)
			return len(p), nil
		}
		n = copy(w.buffer[headerSizeV11+w.offset:], p[:remaining])
		if err = w.encrypt(w.buffer[headerSizeV11:headerSizeV11+maxPayloadSizeV11], false); err != nil {
			return n, err
		}
		p = p[remaining:]
		w.offset = 0
	}
	for len(p) > maxPayloadSizeV11 {
		if err = w.encrypt(p[:maxPayloadSizeV11], false); err != nil {
			return n, err
		}
		p = p[maxPayloadSizeV11:]
		n += maxPayloadSizeV11
	}
	if len(p) > 0 {
		w.offset = copy(w.buffer[headerSizeV11:], p)
		n += w.offset
	}
	return n, nil
}

func (w *encryptedWriterV11) Close() error {
	if w.offset > 0 {
		if err := w.encrypt(w.buffer[headerSizeV11:headerSizeV11+w.offset], true); err != nil {
			return err
		}
		w.offset = 0
	}
	if closer, ok := w.dst.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type decryptedWriterV11 struct {
	dst io.Writer

	ciphers        [2]cipher.AEAD
	sequenceNumber uint32
	refHeader      headerV11 // nil until first write happened

	buffer [maxPackageSizeV11]byte
	offset int

	finalized bool
}

func (w *decryptedWriterV11) decrypt(src []byte) error {
	if w.finalized {
		return errors.New("sio: data after final package")
	}
	pack := packageV11(src)
	header := pack.Header()
	if w.refHeader == nil { // save first header so that we can compare all other headers to it
		w.refHeader = make(headerV11, headerSizeV11)
		copy(w.refHeader, header)
	}

	if header.Version() != Version11 {
		return errors.New("sio: unsupported version")
	}
	if c := header.Cipher(); c > CHACHA20_POLY1305 || w.ciphers[c] == nil || c != w.refHeader.Cipher() {
		return errors.New("sio: unsupported cipher")
	}
	if !header.IsFinal() && header.Length() != maxPayloadSizeV11 {
		return errors.New("sio: invalid payload size")
	}
	refNonce, nonce := w.refHeader.Nonce(), header.Nonce()
	if header.IsFinal() {
		w.finalized = true
		refNonce[0] |= 0x80
		if subtle.ConstantTimeCompare(nonce[:], refNonce[:]) != 1 {
			return errors.New("sio: invalid random value")
		}
	} else if subtle.ConstantTimeCompare(nonce[:], refNonce[:]) != 1 {
		return errors.New("sio: invalid random value")
	}

	var Nonce [12]byte
	copy(Nonce[:], nonce[:])
	binary.LittleEndian.PutUint32(Nonce[8:], binary.LittleEndian.Uint32(Nonce[8:])^w.sequenceNumber)
	w.sequenceNumber++
	plaintext, err := w.ciphers[header.Cipher()].Open(w.buffer[headerSizeV11:headerSizeV11], Nonce[:], pack.Ciphertext(), header.AddData())
	if err != nil {
		return err
	}
	n, err := w.dst.Write(plaintext)
	if err != nil {
		return err
	}
	if n != len(plaintext) {
		return io.ErrShortWrite
	}
	return nil
}

func (w *decryptedWriterV11) Write(p []byte) (n int, err error) {
	if w.offset > 0 {
		remaining := maxPackageSizeV11 - w.offset
		if len(p) <= remaining {
			w.offset += copy(w.buffer[w.offset:], p)
			return len(p), nil
		}
		n = copy(w.buffer[w.offset:], p[:remaining])
		if err = w.decrypt(w.buffer[:]); err != nil {
			return n, err
		}
		p = p[remaining:]
		w.offset = 0
	}
	for len(p) > maxPackageSizeV11 {
		if err = w.decrypt(p[:maxPackageSizeV11]); err != nil {
			return n, err
		}
		p = p[maxPackageSizeV11:]
		n += maxPackageSizeV11
	}
	if len(p) > 0 {
		w.offset = copy(w.buffer[:], p)
		n += w.offset
	}
	return n, nil
}

func (w *decryptedWriterV11) Close() error {
	if w.offset > 0 {
		if w.offset < 33 {
			return errors.New("sio: invalid payload size")
		}
		if err := w.decrypt(w.buffer[:w.offset]); err != nil {
			return err
		}
		w.offset = 0
	}
	if closer, ok := w.dst.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
