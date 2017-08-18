package aead

import (
	"crypto/cipher"
	"io"
)

type encryptedReader struct {
	src    io.Reader
	config Config

	sequenceNumber uint32
	nonce          [8]byte
	cipher         cipher.AEAD

	pack   [headerSize + payloadSize + tagSize]byte
	offset int
}

func (r *encryptedReader) Read(p []byte) (n int, err error) {
	if r.offset > 0 {
		remaining := headerSize + header(r.pack[:]).Len() + tagSize - r.offset
		if len(p) < remaining {
			n = copy(p, r.pack[r.offset:r.offset+len(p)])
			r.offset += n
			return
		}
		n += copy(p, r.pack[r.offset:r.offset+remaining])
		p = p[remaining:]
		r.offset = 0
	}
	for len(p) >= headerSize+payloadSize+tagSize {
		nn, err := io.ReadFull(r.src, r.pack[headerSize:headerSize+payloadSize])
		if err != nil && err != io.ErrUnexpectedEOF {
			return n, err
		}
		r.encrypt(p, nn)
		n += headerSize + nn + tagSize
		p = p[headerSize+nn+tagSize:]
	}
	if len(p) > 0 {
		nn, err := io.ReadFull(r.src, r.pack[headerSize:headerSize+payloadSize])
		if err != nil && err != io.ErrUnexpectedEOF {
			return n, err
		}
		r.encrypt(r.pack[:], nn)
		if headerSize+nn+tagSize < len(p) {
			r.offset = copy(p, r.pack[:headerSize+nn+tagSize])
		} else {
			r.offset = copy(p, r.pack[:len(p)])
		}
		n += r.offset
	}
	return
}

func (r *encryptedReader) encrypt(dst []byte, length int) {
	header := header(dst)
	header.SetVersion(r.config.MaxVersion)
	header.SetCipher(r.config.CipherSuites[0])
	header.SetLen(length)
	header.SetSequenceNumber(r.sequenceNumber)
	header.SetNonce(r.nonce)

	copy(dst[:headerSize], header)
	r.cipher.Seal(dst[headerSize:headerSize], header[4:headerSize], r.pack[headerSize:headerSize+length], header[:4])

	r.sequenceNumber++
}

type decryptedReader struct {
	src    io.Reader
	config Config

	sequenceNumber uint32
	ciphers        []cipher.AEAD

	pack   [headerSize + payloadSize + tagSize]byte
	offset int
}

func (r *decryptedReader) Read(p []byte) (n int, err error) {
	if r.offset > 0 {
		remaining := header(r.pack[:]).Len() - r.offset
		if len(p) < remaining {
			n = copy(p, r.pack[headerSize+r.offset:headerSize+r.offset+len(p)])
			r.offset += n
			return
		}
		n = copy(p, r.pack[headerSize+r.offset:headerSize+r.offset+remaining])
		p = p[remaining:]
		r.offset = 0
	}
	for len(p) >= payloadSize {
		if err = r.readHeader(); err != nil {
			return n, err
		}
		nn, err := r.decrypt(p[:payloadSize])
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
		nn, err := r.decrypt(r.pack[headerSize:])
		if err != nil {
			return n, err
		}
		if nn < len(p) {
			r.offset = copy(p, r.pack[headerSize:headerSize+nn])
		} else {
			r.offset = copy(p, r.pack[headerSize:headerSize+len(p)])
		}
		n += r.offset
	}
	return
}

func (r *decryptedReader) readHeader() error {
	header := header(r.pack[:])
	n, err := io.ReadFull(r.src, header)
	if n > 0 && err == io.ErrUnexpectedEOF {
		return errPackageMismatch
	}
	if err != nil {
		return err
	}
	if err = r.config.verifyHeader(header); err != nil {
		return err
	}
	if header.SequenceNumber() != r.sequenceNumber {
		return errPackageOutOfOrder
	}
	return nil
}

func (r *decryptedReader) decrypt(dst []byte) (n int, err error) {
	header := header(r.pack[:])
	if err = r.config.verifyHeader(header); err != nil {
		return 0, err
	}
	if header.SequenceNumber() != r.sequenceNumber {
		return 0, errPackageOutOfOrder
	}
	ciphertext := r.pack[headerSize : headerSize+header.Len()+tagSize]
	n, err = io.ReadFull(r.src, ciphertext)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return 0, errPackageMismatch
	}
	if err != nil {
		return 0, err
	}
	aeadCipher := r.ciphers[header.Cipher()]
	plaintext, err := aeadCipher.Open(dst[:0], header[4:], ciphertext, header[:4])
	if err != nil {
		return 0, err
	}
	r.sequenceNumber++
	return len(plaintext), nil
}
