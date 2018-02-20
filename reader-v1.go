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

import "io"

type encReaderV1 struct {
	authEncV10
	src io.Reader

	buffer      packageV10
	offset      int
	payloadSize int
}

func (r *encReaderV1) Read(p []byte) (int, error) {
	var n int
	if r.offset > 0 {
		remaining := r.buffer.Length() - r.offset
		if len(p) < remaining {
			n = copy(p, r.buffer[r.offset:r.offset+len(p)])
			r.offset += n
			return n, nil
		}
		n = copy(p, r.buffer[r.offset:r.offset+remaining])
		p = p[remaining:]
		r.offset = 0
	}
	for len(p) >= headerSize+r.payloadSize+tagSize {
		nn, err := io.ReadFull(r.src, p[headerSize:headerSize+r.payloadSize])
		if err != nil && err != io.ErrUnexpectedEOF {
			return n, err
		}
		r.Seal(p, p[headerSize:headerSize+nn])
		n += headerSize + nn + tagSize
		p = p[headerSize+nn+tagSize:]
	}
	if len(p) > 0 {
		nn, err := io.ReadFull(r.src, r.buffer[headerSize:headerSize+r.payloadSize])
		if err != nil && err != io.ErrUnexpectedEOF {
			return n, err
		}
		r.Seal(r.buffer, r.buffer[headerSize:headerSize+nn])
		if length := r.buffer.Length(); length < len(p) {
			r.offset = copy(p, r.buffer[:length])
		} else {
			r.offset = copy(p, r.buffer[:len(p)])
		}
		n += r.offset
	}
	return n, nil
}

type decReaderV1 struct {
	authDecV10
	src io.Reader

	buffer packageV10
	offset int
}

func (r *decReaderV1) Read(p []byte) (n int, err error) {
	if r.offset > 0 {
		payload := r.buffer.Payload()
		remaining := len(payload) - r.offset
		if len(p) < remaining {
			n = copy(p, payload[r.offset:+r.offset+len(p)])
			r.offset += n
			return
		}
		n = copy(p, payload[r.offset:r.offset+remaining])
		p = p[remaining:]
		r.offset = 0
	}
	for len(p) >= maxPayloadSize {
		if err = r.readPackage(r.buffer); err != nil {
			return n, err
		}
		length := len(r.buffer.Payload())
		if err = r.Open(p[:length], r.buffer[:r.buffer.Length()]); err != nil {
			return n, err
		}
		p = p[length:]
		n += length
	}
	if len(p) > 0 {
		if err = r.readPackage(r.buffer); err != nil {
			return n, err
		}
		payload := r.buffer.Payload()
		if err = r.Open(payload, r.buffer[:r.buffer.Length()]); err != nil {
			return n, err
		}
		if len(payload) < len(p) {
			r.offset = copy(p, payload)
		} else {
			r.offset = copy(p, payload[:len(p)])
		}
		n += r.offset
	}
	return
}

func (r *decReaderV1) readPackage(dst packageV10) error {
	header := dst.Header()
	_, err := io.ReadFull(r.src, header)
	if err == io.ErrUnexpectedEOF {
		return errMissingHeader
	}
	if err != nil {
		return err
	}

	_, err = io.ReadFull(r.src, dst.Ciphertext())
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return errPayloadTooShort
	}
	if err != nil {
		return err
	}
	return nil
}
